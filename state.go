// Copyright (c) 2017 Dmitry Voytik <voytikd@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/clearcontainers/proxy/api"
)

// storeStateDir is populated at link time with the value of:
//   $(LOCALSTATEDIR)/lib/clear-containers/proxy/"
var storeStateDir = "/var/lib/clearcontainers/proxy/"

const proxyStateFileName = "proxy_state.json"
const proxyStateDirPerm = 0755
const proxyStateFilesPerm = 0640

// state files format
const stateFormatVersion = 1

// proxyStateOnDisk is used to (re)store proxy state on disk.
// XXX stateFormatVersion must be update in case of any changes in this struct.
type proxyStateOnDisk struct {
	Version         uint     `json:"version"`
	SocketPath      string   `json:"socket_path"`
	EnableVMConsole bool     `json:"enable_vm_console"`
	ContainerIDs    []string `json:"container_ids"`
}

// vmStateOnDisk is used to (re)store vm struct on disk
// XXX stateFormatVersion must be update in case of any changes in this struct.
type vmStateOnDisk struct {
	RegisterVM api.RegisterVM `json:"registerVM"`
	Tokens     []string       `json:"tokens"`
}

func logContID(containerID string) *logrus.Entry {
	return proxyLog.WithField("container", containerID)
}

// On success returns nil, otherwise an error string message.
func (proxy *proxy) restoreTokens(vm *vm, tokens []string) error {
	if vm == nil {
		return fmt.Errorf("vm parameter is nil")
	}

	for _, token := range tokens {
		if token == "" {
			continue
		}

		token, err := vm.AllocateTokenAs(Token(token))
		if err != nil {
			return err
		}

		proxy.Lock()
		proxy.tokenToVM[token] = &tokenInfo{
			state: tokenStateAllocated,
			vm:    vm,
		}
		proxy.Unlock()

		session := vm.findSessionByToken(token)
		if session == nil {
			return fmt.Errorf("unknown token %s", token)
		}

		// Signal that the process is already started
		close(session.processStarted)
	}
	return nil
}

// returns false if it's a clean start (i.e. no state is stored) or restoring
// failed
func (proxy *proxy) restoreState() bool {
	proxyStateFilePath := storeStateDir + proxyStateFileName
	if _, err := os.Stat(storeStateDir); os.IsNotExist(err) {
		err := os.MkdirAll(storeStateDir, proxyStateDirPerm)
		if err != nil {
			proxyLog.Errorf("Couldn't create directory %s: %v",
				storeStateDir, err)
		}
		return false
	}

	fdata, err := ioutil.ReadFile(proxyStateFilePath)
	if err != nil {
		proxyLog.Errorf("Couldn't read state file %s: %v",
			proxyStateFilePath, err)
		return false
	}

	var proxyState proxyStateOnDisk
	err = json.Unmarshal(fdata, &proxyState)
	if err != nil {
		proxyLog.Errorf("Couldn't unmarshal %s: %v",
			proxyStateFilePath, err)
		return false
	}

	proxyLog.Debugf("proxyState: %+v", proxyState)

	if len(proxyState.ContainerIDs) == 0 {
		proxyLog.Warnf("ContainerIDs list is empty")
		return false
	}

	proxyLog.Info("Recovering proxy state from: ", proxyStateFilePath)
	if proxyState.Version > stateFormatVersion {
		proxyLog.Errorf("Stored state format version (%d) is higher "+
			"than supported (%d). Aborting", proxyState.Version,
			stateFormatVersion)
		return false
	}

	proxy.socketPath = proxyState.SocketPath
	proxy.enableVMConsole = proxyState.EnableVMConsole

	for _, containerID := range proxyState.ContainerIDs {
		go func(contID string) {
			// ignore failures here but log them inside
			_ = restoreVMState(proxy, contID)
		}(containerID)
	}

	return true
}

// On success returns nil, otherwise an error string message.
func (proxy *proxy) storeState() error {
	proxyStateFilePath := storeStateDir + proxyStateFileName
	proxy.Lock()
	defer proxy.Unlock()

	// if there are 0 VMs then remove state from disk
	if (len(proxy.vms)) == 0 {
		if _, err := os.Stat(proxyStateFilePath); os.IsNotExist(err) {
			return nil
		}
		if err := os.Remove(proxyStateFilePath); err != nil {
			return fmt.Errorf("Couldn't remove file %s: %v",
				proxyStateFilePath, err)
		}
	}

	proxyState := &proxyStateOnDisk{
		Version:         stateFormatVersion,
		SocketPath:      proxy.socketPath,
		EnableVMConsole: proxy.enableVMConsole,
		ContainerIDs:    make([]string, 0, len(proxy.vms)),
	}

	for cid := range proxy.vms {
		proxyState.ContainerIDs = append(proxyState.ContainerIDs, cid)
	}

	data, err := json.MarshalIndent(proxyState, "", "\t")
	if err != nil {
		return fmt.Errorf("Couldn't marshal proxy state %+v: %v",
			proxyState, err)
	}

	err = ioutil.WriteFile(proxyStateFilePath, data, proxyStateFilesPerm)
	if err != nil {
		return fmt.Errorf("Couldn't store proxy state to file %s: %v",
			proxyStateFilePath, err)
	}
	return nil
}

func vmStateFilePath(id string) string {
	return storeStateDir + "vm_" + id + ".json"
}

// On success returns nil, otherwise an error string message.
func storeVMState(vm *vm, tokens []string) error {
	stVM := vmStateOnDisk{
		RegisterVM: api.RegisterVM{
			ContainerID: vm.containerID,
			CtlSerial:   vm.hyperHandler.GetCtlSockPath(),
			IoSerial:    vm.hyperHandler.GetIoSockPath(),
			Console:     vm.console.socketPath,
		},
		Tokens: tokens,
	}

	o, err := json.MarshalIndent(&stVM, "", "\t")
	if err != nil {
		return fmt.Errorf("Couldn't marshal VM state: %v", err)
	}

	storeFile := vmStateFilePath(vm.containerID)

	err = ioutil.WriteFile(storeFile, o, proxyStateFilesPerm)
	if err != nil {
		return fmt.Errorf("Couldn't store VM state to %s: %v",
			storeFile, err)
	}

	return nil
}

// On success returns nil, otherwise an error string message.
func delVMAndState(proxy *proxy, vm *vm) error {
	if proxy == nil {
		return errors.New("proxy parameter is nil")
	}
	if vm == nil {
		return errors.New("vm parameter is nil")
	}

	logContID(vm.containerID).Infof("Removing on-disk state")

	proxy.Lock()
	delete(proxy.vms, vm.containerID)
	proxy.Unlock()

	if err := proxy.storeState(); err != nil {
		logContID(vm.containerID).Warnf("Couldn't store proxy's state:"+
			" %v", err)
	}

	storeFile := vmStateFilePath(vm.containerID)
	if err := os.Remove(storeFile); err != nil {
		return fmt.Errorf("Couldn't remove file %s: %v", storeFile, err)
	}
	return nil
}

func readVMState(containerID string) (*vmStateOnDisk, error) {
	if containerID == "" {
		return nil, fmt.Errorf("containerID parameter is empty")
	}

	vmStateFilePath := vmStateFilePath(containerID)
	fdata, err := ioutil.ReadFile(vmStateFilePath)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read %s: %v", vmStateFilePath,
			err)
	}

	var vmState vmStateOnDisk
	err = json.Unmarshal(fdata, &vmState)
	if err != nil {
		return nil, fmt.Errorf("Couldn't unmarshal %s: %v",
			vmStateFilePath, err)
	}

	return &vmState, nil
}

func restoreTokens(proxy *proxy, vmState *vmStateOnDisk, vm *vm) error {
	if err := proxy.restoreTokens(vm, vmState.Tokens); err != nil {
		return fmt.Errorf("Failed to restore tokens %+v: %v",
			vmState.Tokens, err)
	}

	for _, token := range vmState.Tokens {
		if token == "" {
			return fmt.Errorf("Empty token in recovering state")
		}

		session := vm.findSessionByToken(Token(token))
		if session == nil {
			_ = delVMAndState(proxy, vm) // errors are irrelevant here
			return fmt.Errorf("Couldn't find a session for token: %s",
				token)
		}

		if err := session.WaitForShim(); err != nil {
			_ = delVMAndState(proxy, vm) // errors are irrelevant here
			return fmt.Errorf("Failed to re-connect with shim "+
				"(token = %s): %v", token, err)
		}
	}
	return nil
}

func restoreVMState(proxy *proxy, containerID string) bool {
	if proxy == nil {
		logContID(containerID).Errorf("proxy parameter is nil")
		return false
	}

	if containerID == "" {
		logContID(containerID).Errorf("containerID is empty. Ignoring.")
		return false
	}

	vmState, err := readVMState(containerID)
	if err != nil {
		logContID(containerID).Error(err)
		return false
	}
	logContID(containerID).Debugf("restoring vm state: %+v", vmState)

	regVM := vmState.RegisterVM
	if regVM.ContainerID == "" || regVM.CtlSerial == "" ||
		regVM.IoSerial == "" {
		logContID(containerID).Errorf("wrong VM parameters")
		return false
	}

	if regVM.ContainerID != containerID {
		logContID(containerID).Errorf("Inconsistent container ID: %s",
			regVM.ContainerID)
		return false
	}

	proxy.Lock()
	if _, ok := proxy.vms[regVM.ContainerID]; ok {
		proxy.Unlock()
		logContID(containerID).Errorf("container already registered")
		return false
	}
	vm := newVM(regVM.ContainerID, regVM.CtlSerial, regVM.IoSerial)
	proxy.vms[regVM.ContainerID] = vm
	proxy.Unlock()

	proxyLog.WithFields(logrus.Fields{
		"container":       regVM.ContainerID,
		"control-channel": regVM.CtlSerial,
		"io-channel":      regVM.IoSerial,
		"console":         regVM.Console,
	}).Info("restoring state")

	if regVM.Console != "" && proxy.enableVMConsole {
		vm.setConsole(regVM.Console)
	}

	if err := restoreTokens(proxy, vmState, vm); err != nil {
		logContID(containerID).Errorf("Error restoring tokens: %v", err)
		return false
	}

	if err := vm.Reconnect(true); err != nil {
		logContID(containerID).Errorf("Failed to connect: %v", err)
		if err := delVMAndState(proxy, vm); err != nil {
			logContID(containerID).Errorf("Failed to delete vm's "+
				"state: %v", err)
		}
		return false
	}

	// We start one goroutine per-VM to monitor the qemu process
	proxy.wg.Add(1)
	go func() {
		<-vm.OnVMLost()
		vm.Close()
		proxy.wg.Done()
	}()

	return true
}

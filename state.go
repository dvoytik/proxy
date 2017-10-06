// Copyright (c) 2017 Intel Corporation
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
	"fmt"
	"github.com/clearcontainers/proxy/api"
	"io/ioutil"
	"os"
)

// storeStateDir is populated at link time with the value of:
//   $(LOCALSTATEDIR)/lib/clear-containers/proxy/"
var storeStateDir = "/var/lib/clearcontainers/proxy/"

const proxyStateFileName = "proxy_state.json"
const proxyStateDirPerm = 0755
const proxyStateFilesPerm = 0640

// proxyStateOnDisk is used to (re)store proxy state on disk
type proxyStateOnDisk struct {
	Version         string   `json:"version"`
	SocketPath      string   `json:"socket_path"`
	EnableVMConsole bool     `json:"enable_vm_console"`
	ContainerIDs    []string `json:"container_ids"`
}

// vmStateOnDisk is used to (re)store vm struct on disk
type vmStateOnDisk struct {
	RegisterVM api.RegisterVM `json:"registerVM"`
	Tokens     []string       `json:"tokens"`
}

func (proxy *proxy) restoreTokens(vm *vm, tokens []string) error {
	if vm == nil {
		return fmt.Errorf("vm parameter must be not nil")
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

// returns false if it's a clean start (i.e. no state is stored) or restoring failed
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
		proxyLog.Errorf("Couldn't read state file %s: %v", proxyStateFilePath, err)
		return false
	}

	var proxyState proxyStateOnDisk
	err = json.Unmarshal(fdata, &proxyState)
	if err != nil {
		proxyLog.Errorf("Couldn't unmarshal %s: %v", proxyStateFilePath, err)
		return false
	}
	proxyLog.Debugf("proxy: %+v", proxyState)

	if len(proxyState.ContainerIDs) == 0 {
		return false
	}
	proxyLog.Warn("Recovering proxy state from: ", proxyStateFilePath)
	if proxyState.Version != Version {
		proxyLog.Warnf("Stored state version (%s) mismatches proxy"+
			" version (%s). Aborting", proxyState.Version, Version)
		return false
	}

	proxy.socketPath = proxyState.SocketPath
	proxy.enableVMConsole = proxyState.EnableVMConsole

	for _, contID := range proxyState.ContainerIDs {
		go restoreVMState(proxy, contID)
	}

	return true
}

func (proxy *proxy) storeState() {
	proxyStateFilePath := storeStateDir + proxyStateFileName
	proxy.Lock()
	defer proxy.Unlock()

	// if there are 0 VMs then remove state from disk
	if (len(proxy.vms)) == 0 {
		if err := os.Remove(proxyStateFilePath); err != nil {
			proxyLog.Errorf("Couldn't remove %s: %v",
				proxyStateFilePath, err)
		}
		return
	}

	proxyState := &proxyStateOnDisk{
		Version:         Version,
		SocketPath:      proxy.socketPath,
		EnableVMConsole: proxy.enableVMConsole,
		ContainerIDs:    make([]string, 0, len(proxy.vms)),
	}

	for cid := range proxy.vms {
		proxyState.ContainerIDs = append(proxyState.ContainerIDs, cid)
	}

	data, err := json.MarshalIndent(proxyState, "", "\t")
	if err != nil {
		proxyLog.Errorf("Couldn't marshal proxy state %+v: %v",
			proxyState, err)
	}

	err = ioutil.WriteFile(proxyStateFilePath, data, proxyStateFilesPerm)
	if err != nil {
		proxyLog.Errorf("Couldn't store proxy state to %s: %v",
			proxyStateFilePath, err)
	}
}

func vmStateFilePath(id string) string {
	return storeStateDir + "vm_" + id + ".json"
}

func storeVMState(vm *vm, tokens []string) {
	odVM := vmStateOnDisk{
		RegisterVM: api.RegisterVM{
			ContainerID: vm.containerID,
			CtlSerial:   vm.hyperHandler.GetCtlSockPath(),
			IoSerial:    vm.hyperHandler.GetIoSockPath(),
			Console:     vm.console.socketPath,
		},
		Tokens: tokens,
	}
	o, err := json.MarshalIndent(&odVM, "", "\t")
	if err != nil {
		proxyLog.WithField("vm", vm.containerID).Warnf(
			"Couldn't marshal VM state: %v", err)
		return
	}

	storeFile := vmStateFilePath(vm.containerID)

	err = ioutil.WriteFile(storeFile, o, proxyStateFilesPerm)
	if err != nil {
		proxyLog.WithField("vm", vm.containerID).Warnf(
			"Couldn't store VM state to %s: %v", storeFile, err)
	}
}

func delVMAndState(proxy *proxy, vm *vm) {
	if proxy == nil {
		proxyLog.Error("proxy parameter must be not nil")
		return
	}
	if vm == nil {
		proxyLog.Error("vm parameter must be not nil")
		return
	}

	proxyLog.Infof("Removing on-disk state of %s", vm.containerID)

	proxy.Lock()
	delete(proxy.vms, vm.containerID)
	proxy.Unlock()

	proxy.storeState()
	storeFile := vmStateFilePath(vm.containerID)
	if err := os.Remove(storeFile); err != nil {
		proxyLog.WithField("vm", vm.containerID).Warnf(
			"Couldn't remove file %s: %v", storeFile, err)
	}
}

func readVMState(containerID string) *vmStateOnDisk {
	if containerID == "" {
		proxyLog.Errorf("containerID parameter must be not empty")
		return nil
	}

	vmStateFilePath := vmStateFilePath(containerID)
	fdata, err := ioutil.ReadFile(vmStateFilePath)
	if err != nil {
		proxyLog.Errorf("Couldn't read %s: %v", vmStateFilePath, err)
		return nil
	}

	var vmState vmStateOnDisk
	err = json.Unmarshal(fdata, &vmState)
	if err != nil {
		proxyLog.Errorf("Couldn't unmarshal %s: %v", vmStateFilePath, err)
		return nil
	}

	proxyLog.Debugf("restoring vm state: %+v", vmState)
	return &vmState
}

func restoreTokens(proxy *proxy, vmState *vmStateOnDisk, vm *vm) {
	if err := proxy.restoreTokens(vm, vmState.Tokens); err != nil {
		proxyLog.Errorf("Failed to restore tokens: %v", err)
		return
	}

	for _, token := range vmState.Tokens {
		session := vm.findSessionByToken(Token(token))
		if session == nil {
			proxyLog.Errorf("Session must be not nil")
			delVMAndState(proxy, vm)
			return
		}
		if err := session.WaitForShim(); err != nil {
			proxyLog.Errorf("Failed to re-connect with shim: %v", err)
			delVMAndState(proxy, vm)
			return
		}
	}
}

func restoreVMState(proxy *proxy, containerID string) {
	if proxy == nil {
		proxyLog.Errorf("proxy parameter must be not nil")
		return
	}

	vmState := readVMState(containerID)
	if vmState == nil {
		return
	}

	regVM := vmState.RegisterVM
	if regVM.ContainerID == "" || regVM.CtlSerial == "" || regVM.IoSerial == "" {
		proxyLog.Errorf("wrong VM parameters")
		return
	}

	proxy.Lock()
	if _, ok := proxy.vms[regVM.ContainerID]; ok {
		proxy.Unlock()
		proxyLog.Errorf("%s: container already registered", regVM.ContainerID)
		return
	}
	vm := newVM(regVM.ContainerID, regVM.CtlSerial, regVM.IoSerial)
	proxy.vms[regVM.ContainerID] = vm
	proxy.Unlock()

	proxyLog.Infof("restoreVMState(containerId=%s,ctlSerial=%s,ioSerial=%s,console=%s)",
		regVM.ContainerID, regVM.CtlSerial, regVM.IoSerial, regVM.Console)

	if regVM.Console != "" && proxy.enableVMConsole {
		vm.setConsole(regVM.Console)
	}

	restoreTokens(proxy, vmState, vm)
	if err := vm.Reconnect(true); err != nil {
		proxyLog.Errorf("Failed to connect: %v", err)
		delVMAndState(proxy, vm)
		return
	}

	// We start one goroutine per-VM to monitor the qemu process
	proxy.wg.Add(1)
	go func() {
		<-vm.OnVMLost()
		vm.Close()
		proxy.wg.Done()
	}()
}

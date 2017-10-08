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
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/Sirupsen/logrus/hooks/test"
	"github.com/clearcontainers/proxy/api"
	"github.com/stretchr/testify/assert"
)

func TestState_restoreTokens(t *testing.T) {
	a := assert.New(t)

	rig := newTestRig(t)
	rig.Start()
	proxy := rig.proxy
	ctlSocketPath, ioSocketPath := rig.Hyperstart.GetSocketPaths()
	tVM := newVM(testContainerID, ctlSocketPath, ioSocketPath)
	a.NotNil(tVM)

	// vm == nil
	e := proxy.restoreTokens(nil, []string{})
	a.EqualError(e, "vm parameter is nil")

	// ignores empty list of tokens
	a.Nil(proxy.restoreTokens(tVM, []string{}))
	a.Equal(len(proxy.tokenToVM), 0)

	// registers token1
	a.Nil(proxy.restoreTokens(tVM, []string{"token1"}))
	a.Equal(proxy.tokenToVM["token1"], &tokenInfo{
		state: tokenStateAllocated,
		vm:    tVM,
	})

	// vm == nil
	e = restoreTokens(proxy, &vmStateOnDisk{}, nil)
	a.EqualError(e, "Failed to restore tokens []: vm parameter is nil")

	// ignores empty list of tokens
	emptyListOfTokens := []string{}
	a.Nil(restoreTokens(rig.proxy, &vmStateOnDisk{api.RegisterVM{},
		emptyListOfTokens}, &vm{}))

	e = restoreTokens(rig.proxy, &vmStateOnDisk{api.RegisterVM{},
		[]string{""}}, &vm{})
	a.EqualError(e, "Empty token in recovering state")

	proxy.Lock()
	proxy.vms[testContainerID] = tVM
	proxy.Unlock()
	go tVM.AssociateShim(Token("token2"), 1, nil)
	a.Nil(restoreTokens(proxy, &vmStateOnDisk{api.RegisterVM{
		ContainerID: testContainerID, CtlSerial: "", IoSerial: "",
		Console: "", NumIOStreams: 1}, []string{"token2"}}, tVM))
}

func TestState_restoreState(t *testing.T) {
	a := assert.New(t)
	proxyStateFilePath := storeStateDir + proxyStateFileName
	rig := newTestRig(t)
	rig.Start()
	lh := test.NewGlobal()

	// clean up a possible state
	a.Nil(os.RemoveAll(storeStateDir))

	// Nothing to restore
	a.False(rig.proxy.restoreState())
	a.Nil(lh.LastEntry())

	a.Nil(os.MkdirAll(storeStateDir, 0750))

	// Fails to restore from an inaccessible file (permission denied)
	a.Nil(ioutil.WriteFile(proxyStateFilePath, []byte{' '}, 0000))
	a.False(rig.proxy.restoreState())
	expectedLogMessage := "Couldn't unmarshal " + proxyStateFilePath +
		": unexpected end of JSON input"
	a.Equal(expectedLogMessage, lh.LastEntry().Message)
	a.Nil(os.Remove(proxyStateFilePath))

	// Fails to restore from an empty file
	a.Nil(ioutil.WriteFile(proxyStateFilePath, []byte(""), 0600))
	a.False(rig.proxy.restoreState())
	a.Equal(expectedLogMessage, lh.LastEntry().Message)

	// Fails to restore from garbage
	a.Nil(ioutil.WriteFile(proxyStateFilePath, []byte("Hello, World!"), 0600))
	a.False(rig.proxy.restoreState())
	expectedLogMessage = "Couldn't unmarshal " + proxyStateFilePath +
		": invalid character 'H' looking for beginning of value"
	a.Equal(expectedLogMessage, lh.LastEntry().Message)

	// Fails to restore when ContainerIDs list is empty
	const s = `{ "container_ids": [ ] }`
	a.Nil(ioutil.WriteFile(proxyStateFilePath, []byte(s), 0600))
	a.False(rig.proxy.restoreState())
	expectedLogMessage = "ContainerIDs list is empty"
	a.Equal(expectedLogMessage, lh.LastEntry().Message)

	// Fails to restore when stored Version is higher
	sVer := fmt.Sprintf(`{ "version": %d, "container_ids": [ "09876543210" ] }`, stateFormatVersion+1)
	a.Nil(ioutil.WriteFile(proxyStateFilePath, []byte(sVer), 0600))
	a.False(rig.proxy.restoreState())
	expectedLogMessage = fmt.Sprintf("Stored state format version (%d) is higher "+
		"than supported (%d). Aborting", stateFormatVersion+1, stateFormatVersion)
	a.Equal(expectedLogMessage, lh.LastEntry().Message)

	a.Nil(os.Remove(proxyStateFilePath))

	// Success
	rig.RegisterVM()
	rig.Stop()
	rig = newTestRig(t)
	rig.Start()
	a.True(rig.proxy.restoreState())
}

func lastLogEq(a *assert.Assertions, lh *test.Hook, msg string) {
	entry := lh.LastEntry()
	if a.NotNil(entry) {
		a.Equal(entry.Message, msg)
	}
}

func TestState_storeState(t *testing.T) {
	a := assert.New(t)
	proxyStateFilePath := storeStateDir + proxyStateFileName
	rig := newTestRig(t)
	rig.Start()
	proxy := rig.proxy
	a.NotNil(proxy)

	// Success: 0 vm to store, no proxy's state file
	a.Nil(os.RemoveAll(storeStateDir))
	a.Nil(proxy.storeState())

	// Fails to store a state to a file
	a.Nil(os.MkdirAll(storeStateDir, 0600))
	rig.RegisterVM()
	a.Nil(os.RemoveAll(storeStateDir))
	a.EqualError(proxy.storeState(), fmt.Sprintf("Couldn't store proxy "+
		"state to file %s: open %s: no such file or directory",
		proxyStateFilePath, proxyStateFilePath))
}

func TestState_storeVMState(t *testing.T) {
	a := assert.New(t)
	rig := newTestRig(t)
	rig.Start()
	proxy := rig.proxy
	a.NotNil(proxy)

	a.Equal(vmStateFilePath(testContainerID), storeStateDir+"vm_"+
		testContainerID+".json")

	// clean up a possible state
	a.Nil(os.RemoveAll(storeStateDir))
	a.Nil(os.MkdirAll(storeStateDir, 0750))

	token := rig.RegisterVM()
	vm := proxy.vms[testContainerID]
	a.NotNil(vm)

	// Success to store vm's state
	a.Nil(storeVMState(vm, []string{token}))

	// Fails to write file
	a.Nil(os.RemoveAll(storeStateDir))
	a.EqualError(storeVMState(vm, []string{token}),
		fmt.Sprintf("Couldn't store VM state to %s: open %s: no such"+
			" file or directory", vmStateFilePath(testContainerID),
			vmStateFilePath(testContainerID)))
}

func TestState_delVMAndState(t *testing.T) {
	a := assert.New(t)
	//proxyStateFilePath := storeStateDir + proxyStateFileName
	rig := newTestRig(t)
	rig.Start()
	proxy := rig.proxy
	a.NotNil(proxy)

	// clean up a possible state
	a.Nil(os.RemoveAll(storeStateDir))
	a.Nil(os.MkdirAll(storeStateDir, 0750))

	a.EqualError(delVMAndState(nil, nil), "proxy parameter is nil")
	a.EqualError(delVMAndState(proxy, nil), "vm parameter is nil")

	// Fail to delete a file
	token := rig.RegisterVM()
	vm := proxy.vms[testContainerID]
	a.Nil(storeVMState(vm, []string{token}))
	a.Nil(os.RemoveAll(storeStateDir))
	a.EqualError(delVMAndState(proxy, vm),
		fmt.Sprintf("Couldn't remove file %s: remove %s: no such"+
			" file or directory", vmStateFilePath(testContainerID),
			vmStateFilePath(testContainerID)))

	// TODO: success
}

/*
func TestState_StoreRestore(t *testing.T) {
	assert := assert.New(t)

	// clean up a possible state
	os.RemoveAll(storeStateDir)

	rig := newTestRig(t)
	rig.Start()

	assert.False(rig.proxy.restoreState())

	rig.RegisterVM()
	rig.Stop()
	// the state expected to be present on a disk
	files, err := ioutil.ReadDir(storeStateDir)
	assert.Nil(err)
	assert.Equal(len(files), 2)
	assert.Equal(files[0].Name(), proxyStateFileName)
	assert.Equal(files[1].Name(), "vm_"+testContainerID+".json")

	rig.Start()
	assert.Equal(rig.proxy.restoreState(), true)
	assert.Nil(rig.Client.UnregisterVM(testContainerID))
	// the state must be absent on the disk
	files, err = ioutil.ReadDir(storeStateDir)
	assert.Nil(err)
	assert.Equal(len(files), 0)
	os.RemoveAll(storeStateDir)
}

func TestStoreRestoreInvalidState(t *testing.T) {
	assert := assert.New(t)
	//proxyStateFilePath := storeStateDir + "proxy_state.json"
	rig := newTestRig(t)
	rig.Start()

	// clean up a possible state
	os.RemoveAll(storeStateDir)
	assert.Nil(os.MkdirAll(storeStateDir, 0750))

	// wrong parameters
	restoreVMState(nil, "")
	assert.Nil(readVMState(""))

	vmStateFile := storeStateDir + "vm_" + testContainerID + ".json"
	// restore from an inaccessible file (no such file or directory)
	assert.Nil(readVMState(testContainerID))

	// restore from garbage
	assert.Nil(ioutil.WriteFile(vmStateFile, []byte("Garbage"), 0600))
	assert.Nil(readVMState(testContainerID))
	assert.Nil(os.Remove(vmStateFile))

	// ContainerID is empty
	const sVM = `{ "registerVM": { "containerId": "" } } `
	assert.Nil(ioutil.WriteFile(vmStateFile, []byte(sVM), 0600))
	restoreVMState(rig.proxy, testContainerID)

	os.RemoveAll(storeStateDir)
}
*/

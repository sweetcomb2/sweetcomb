# Release Notes    {#release notes

* @subpage release_notes_1904
* @subpage release_notes_1901

@page release_notes_1904 Release notes for Sweetcomb 19.04

## Northbound Interface
- Init gNMI Server

## NAT
- Add IETF NAT Yang Models.
- Add IETF NAT Translation Layer.
- Add IETF NAT test cases.

## High Availability
- Add vpp health check.

## Code Refactor
- Code global cleanup.
- Refactor build system.
- Rework scvpp to be only interface with VAPI.
- Rework interface and local routing to leverage new scvpp.

## Test Framework
- Add unit test framework.
- Add unit test suite for interface and local routing.
- Build docker environment to test integration of sweetcomb and VPP.


@page release_notes_1901 Release notes for Sweetcomb 19.01

## Features

### Northbound Interface
- Netconf
- gRPC Network Management Interface

### IETF Yang Models
- ietf-interfaces@2014-05-08.yang
- ietf-interfaces.yang
- ietf-ip@2014-06-16.yang
- ietf-yang-types@2013-07-15.yang

### OpenConfig Yang Models
- openconfig-extensions.yang
- openconfig-if-aggregate.yang
- openconfig-if-ethernet.yang
- openconfig-if-ip.yang
- openconfig-if-types.yang
- openconfig-inet-types.yang
- openconfig-interfaces.yang
- openconfig-local-routing.yang
- openconfig-policy-types.yang
- openconfig-types.yang
- openconfig-vlan-types.yang
- openconfig-vlan.yang
- openconfig-yang-types.yang

### Data Store
- Sysrepo configuration
- Sysrepo operational

### Translation Layer: IETF
- interface

### Translation Layer: OpenConfig
- interface
- local routing

### Connection to VPP
- connection to VPP's binary API 


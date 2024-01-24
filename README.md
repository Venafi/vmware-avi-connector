[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)

# vmware-avi-connector
Sample TLSPC machine connector 

# Dependencies
Below are the minimal dependency version that are required to build ....
- GNU Make 3.81
- jq - commandline JSON processor [version 1.6]
- go version go1.20
- Docker version 24.0.7
- golangci-lint has version 1.52.2

# Setting up environment variables
To build an image that will be run within a Venafi Satellite for provision and/or discovery operations you will need to define a CONTAINER_REGISTRY environment variable.

```bash
export CONTAINER_REGISTRY=company.jfrog.io/connectors/vmware
```

> **_NOTE:_** The image, push and manifests make targets will fail if no CONTAINER_REGISTRY value is set. 

> **_NOTE:_** Venafi developer documentation is available at ? 

# Provisioning Connector Basics

## Venafi Satellite

## Manifest

## Testing Access

## Installing a Certificate, Private Key and Issuing Chain

## Configuring Usage of an installed Certificate, Private Key and Issuing Chain

# Discovery Connector Basics

## Discovering Certificates, Issuing Chains and the usage

# Code Structure

# Building

## Binary

## Container Image

# Testing


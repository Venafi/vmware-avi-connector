[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)

# vmware-avi-connector
Sample TLS Protect Cloud machine connector 


# Dependencies
Below are the minimal dependency versions that are required to build:
- GNU Make 3.81
- `jq` - commandline JSON processor [version 1.6]
- go version go1.20
- Docker version 24.0.7
- `golangci-lint` version 1.52.2


# Setting up environment variables
To build an image that will be run within a Venafi Satellite for provisioning and/or discovery operations, you will need to define a CONTAINER_REGISTRY environment variable.

```bash
export CONTAINER_REGISTRY=company.jfrog.io/connectors/vmware
```

> **_NOTE:_** The image, push and manifests make targets fail if no CONTAINER_REGISTRY value is set. 


# Venafi Satellite
A Venafi Satellite is a customer-hosted infrastructure component designed to provide certain functionality within the customer's network, such as private network discovery and integrations, among other services. The Venafi Satellite provides private services within a customer's network by making communications from the customer network to TLS Protect Cloud, requiring only outbound communication and connectivity to manage endpoints.

To support integrations with other systems, such as a VMware NSX Advanced Load Balancer, developers can create a machine connector to perform predefined functions.   A machine connector is a plugin that acts as a middleware to communicate between the Venafi Platform and any 3rd party applications. The connector is responsible for authenticating, pushing, and configuring the certificate from Venafi to any application of the developer's choice.

In the Venafi world, every connector is a REST-based web service with certain predefined APIs implemented to perform a specific provisioning or discovery task. A machine connector is composed of three parts.
- An executable that is run within a container.  The executable uses a web framework to receive incoming requests from a service within the Venafi Satellite.  The request is processed, and the response is returned to the internal service, which then sends the result to VaaS.
- A manifest that defines a series of data structures used during different operations.
  - The manifest MUST define the properties required for connecting to the target and the properties for storing a certificate, private key, and the issuing certificate chain (e.g., the keystore properties).
  - The manifest can optionally define the properties needed to reconfigure the target to use the newly installed certificate, such as restarting a service (e.g., the binding properties).
- A container image that is compatible with the executable.  It is strongly recommended that the image also contain the manifest.json so that if a change to the manifest is made but not to the executable code, then the container image SHA256 digest will also be changed.

Additional resources for developing a machine connector are available at [Venafi Dev Central](https://developer.venafi.com/tlsprotectcloud/docs/libraries-and-sdks-connector-framework)


# Provisioning Connector Basics
A machine connector must always support provisioning a certificate, private key and the issuing certificate chain to a target such as a VMware NSX Advanced Load Balancer (Avi).

## Manifest
The manifest.json file contains the definitions for connection, provisioning, and discovery operations.  These definitions are also used in the TLS Protect Cloud UI for using the machine connector.
As data is exchanged with the machine connector that data is validated against the manifest.json file.  The only field names and values permitted are those defined within the file.  For example, if the connection JSON node defines a username and a password property, then only those field names and values are sent to the machine connector as part of the connection data.  Additionally, only field names and values defined in the keystore node are permitted as a response to a discovery operation.

The manifest is a JSON document with a defined structure and required nodes.  The top-level node must have the following fields:
- ___name___: the required name of the machine connector, such as "VMware NSX Advanced Load Balancer (AVI)".  This value is shown in the TLS Protect Cloud UI.
- ___pluginType___: a required field for a machine connector, and the value must be "MACHINE"
- ___workTypes___: a required collection of strings indicating the capabilities of the machine connector.  All machine connectors are required to support provisioning operations and must have a value of "PROVISIONING" in the collection.  Optionally, if the machine connector supports discovery, the value "DISCOVERY" should also be included.

Additionally, the top-level node should contain the following:
- ___deployment___: a required node that contains the image location that will be used by the Venafi Satellite to pull the container.
    - ___executionTarget___: a required field with the value "vsat".
    - ___image___: the required container registry and image path used to pull the container image.
- ___domainSchema___: a required node that contains definitions for connection, provisioning, and discovery operations.

## User Interface
The TLS Protect Cloud user interface for a machine connector is dynamically rendered using the definitions within the manifest.  The property definitions in the domainSchema node are evaluated as the user interface is rendered.  Property labels and descriptions are mapped from the property definition using the x-labelLocalizationKey field where the value contains a dotted path to within a language in the `localizationResources` node. 

- ___localizationResources___: a required top-level node containing the text shown in the TLS Protect Cloud UI.
  - ___en___: a required node containing the English language localization values.  The definitions contained within this node are mapped to the x-labelLocalizationKey fields defined on properties in the manifest.
    - ___address___: a node containing the localization fields for properties having an x-labelLocalizationKey values beginning with the address.
      - ___label___: the value for properties with x-labelLocalizationKey value of "address.label".

## Routes
All machine connectors must support provisioning operations.  These operations include testing access to the device host (e.g., testConnection), installing a certificate, private key, and the issuing certificate chain (e.g., installCertificateBundle), and configuring usage of an installed certificate (e.g., configureInstallationEndpoint).

If a machine connector supports discovery operations, then a definition for performing a discovery is also required (e.g., discoverCertificates).

- ___hooks___: a required top level node containing the mapping and requestConverters nodes.
  - ___mapping___: a required node defining the operations and the corresponding REST URL path.  Each of the required sub-nodes _MUST HAVE_ a path definition containing the REST URL path to be used to execute the corresponding operation.
    - _configureInstallationEndpoint_: a required node for configuring an installation endpoint operation.
    - _installCertificateBundle_: a required node for installing a certificate, private key, and issuing certificate chain.
    - _testConnection_: a required node for a test connection.
    - _discoverCertificates_: a required node if the connector supports the DISCOVERY work type.
    - _getTargetConfiguration_: an optional node for an unused operation.
  - ___requestConverters___: a required array of named converters.  If any manifest property has an x-encrypted field with a value of true, the collection must contain the value of "arguments-decrypter". 

## Responses
The response for a machine connector operation, such as testConnection, must be an HTTP status code:
- between 200 (OK) and 299, inclusive, indicating a successful operation; or,
- between 400 (Bad Request) and 499, inclusive, indicating a failed operation.

> **_NOTE_**: Venafi reserves the usage of HTTP 5xx status codes to indicate a failure within the Venafi Satellite logic.

The response body for a failed operation should be a simple error message string shown to the user and logged by TLS Protect Cloud.

## Testing Access
The data required to test connectivity with a device host can be defined in the connection node of the domainSchema node.  These fields can include hostname / IP address, port, username, and password. For example:

- ___connection___: a node within the domainSchema node that defines the properties needed to perform a connection test with the device host.
  - _properties_: a collection of nodes defining the property values needed to perform a connection to the device host.
  - _required_: an optional collection of property names indicating that a value is required for the corresponding property.
  - _type_: a required field that has a value of "object".

In this sample machine connector, the connection definition is:
```json
  "connection": {
    "allOf": [
      {
        "if": {
          "properties": {
            "credentialType": {
              "const": "local"
            }
          },
          "required": [
            "credentialType"
          ]
        },
        "then": {
          "required": [
            "credentialType",
            "username",
            "password"
          ]
        }
      },
      {
        "if": {
          "properties": {
            "credentialType": {
              "const": "shared"
            }
          },
          "required": [
            "credentialType"
          ]
        },
        "then": {
          "required": [
            "credentialType",
            "credentialId"
          ]
        }
      }
    ],
    "properties": {
      "credentialId": {
        "description": "credentialId.description",
        "type": "string",
        "x-credential": {
          "authType": "username_password",
          "value": "#/properties/credentialId",
          "mapping": {
            "username": "#/username",
            "password": "#/password"
          }
        },
        "x-labelLocalizationKey": "credentialId.label",
        "x-rank": 3,
        "x-rule": {
          "effect": "SHOW",
          "condition": {
            "scope": "#/properties/credentialType",
            "schema": {
              "const": "shared"
            }
          }
        }
      },
      "credentialType": {
        "default": "local",
        "description": "credentialType.description",
        "oneOf": [
          {
            "const": "local",
            "title": "credentialType.local"
          },
          {
            "const": "shared",
            "title": "credentialType.shared"
          }
        ],
        "x-featureKey": "credential_manager_cyberark",
        "x-labelLocalizationKey": "credentialType.label",
        "x-rank": 2
      },
      "hostnameOrAddress": {
        "type": "string",
        "x-labelLocalizationKey": "address.label",
        "x-rank": 0
      },
      "password": {
        "type": "string",
        "x-controlOptions": {
          "password": true,
          "showPasswordLabel": "password.showPassword",
          "hidePasswordLabel": "password.hidePassword"
        },
        "x-encrypted": true,
        "x-labelLocalizationKey": "password.label",
        "x-rank": 4,
        "x-rule": {
          "effect": "SHOW",
          "condition": {
            "scope": "#/properties/credentialType",
            "schema": {
              "const": "local"
            }
          }
        }
      },
      "port": {
        "description": "port.description",
        "maximum": 65535,
        "minimum": 1,
        "type": "integer",
        "x-labelLocalizationKey": "port.label",
        "x-rank": 1
      },
      "username": {
        "type": "string",
        "x-encrypted": true,
        "x-labelLocalizationKey": "username.label",
        "x-rank": 3,
        "x-rule": {
          "effect": "SHOW",
          "condition": {
            "scope": "#/properties/credentialType",
            "schema": {
              "const": "local"
            }
          }
        }
      }
    },
    "required": [
      "hostnameOrAddress",
      "credentialType"
    ],
    "type": "object"
  }
```

The connection property definitions are used to render the TLS Protect Cloud user interface.  The values provided are included in the testConnection operation request document.

![alt text](images/Local%20Credentials.png)

## Shared Credentials
TLS Protect Cloud provides integration with access management solutions for supporting the usage of shared credentials.  A machine connector can support both manual credential entry and shared credentials within the connection node of the domainSchema definition.

The first property to define is a selector to allow the user to choose either manual (or local) credentials or to use a shared credential when creating a new machine:
```json
  "credentialType": {
      "default": "local",
      "description": "credentialType.description",
      "oneOf": [
          {
              "const": "local",
              "title": "credentialType.local"
          },
          {
              "const": "shared",
              "title": "credentialType.shared"
          }
      ],
      "x-featureKey": "credential_manager_cyberark",
      "x-labelLocalizationKey": "credentialType.label",
      "x-rank": 2
  },
```

Next, on the username and password properties (in this example), we will define an x-rule to indicate that the fields should only be presented to the user if the selected credentialType is "local":
```json
  "x-rule": {
      "effect": "SHOW",
      "condition": {
          "scope": "#/properties/credentialType",
          "schema": {
              "const": "local"
          }
      }
  }
```

Finally, we will include a credentialId property that is rendered when the selected credentialType is "shared":
```json
  "credentialId": {
      "description": "credentialId.description",
      "type": "string",
      "x-credential": {
          "authType": "username_password",
          "value": "#/properties/credentialId",
          "mapping": {
              "username": "#/username",
              "password": "#/password"
          }
      },
      "x-labelLocalizationKey": "credentialId.label",
      "x-rank": 3,
      "x-rule": {
          "effect": "SHOW",
          "condition": {
              "scope": "#/properties/credentialType",
              "schema": {
                  "const": "shared"
              }
          }
      }
  },
```
> **_NOTE_**: Supporting shared credentials requires that the property names are explicitly credentialId and credentialType (as shown above).

> **_NOTE_**: The value property in the x-credential must be the path to the credentialId property name.

When a new machine is created, the rendered UI will change the credentialId from a type of string to a type of oneOf.  The rendering will present the user with a selector allowing them to choose one of their configured shared credentials that are retrieved during rendering.  This allows the final entity to be validated against this manifest where the stated credentialId type is a string, and the value will be one of the customer's configured credential IDs.

![alt text](images/Shared%20Credentials.png)

When a shared credential is selected, the "x-credential" mapping definition defines where the shared credential field values will be copied to.  The types of credentials supported are "username_password" and "password".

To support a "username_password" shared credential, the "x-credential" mapping definition keys MUST include "username" and "password".  The values for these keys are the property names in the connection node properties definition where the corresponding shared credential values are mapped.  For example, if a username and password shared credential holds a username field with the value "SharedUsername" and a password field with the value "SharedPassword" then the "x-credential" mapping definition defines which connection node properties the values are copied to.  In this example the mapping indicates that the shared credential username property value is copied to the connection username property:
```json
  "connection": {
    "hostnameOrAddress": "sample.io",
    "password": "SharedPassword",
    "port": 443,
    "username": "SharedUsername"
  }
```

To support a password shared credential, the "x-credential" mapping definition keys MUST include the key "password". The value is the connection property where the shared credential password value is placed.

Each time an operation is performed the shared current version of the shared credential is retrieved and the values copied into the connection properties.

## Data Security
All properties with an "x-encrypted" flag with a value of true are encrypted by the browser using the customer's Venafi Satellites data encryption key.  When a machine connector request is received by a Venafi Satellite, the request identifies which property values are encrypted.  Those values are then decrypted by the Venafi Satellite to their clear text values.  Next, a new request body (including the now decrypted values) is generated and then encrypted using a key that is exclusive to the machine connector.

When the machine connector receives the request, the request body is automatically decrypted before being passed to the registered REST endpoint handler.  This decryption is added as middleware in the function _addPayloadEncryptionMiddleware_ in internal/handler/web/web.go.  The Venafi Satellite generates the key pair when deploying the machine connector container within the cluster.

## Installing a Certificate, Private Key, and Issuing Chain
All machine connectors must support provisioning operations.  When a certificate is provisioned using a machine connector, the certificate, private key, and issuing certificate chain are sent to the connector using Venafi defined certificateBundle definition and the developer defined keystore in the manifest domainSchema node. 

- ___keystore___: a required node within the domainSchema, defining the properties needed to determine how a certificate, private-key, and the issuing certificate chain are stored on the device host.  In this machine connector, the property definitions are:
  - _certificateName_: The name for how the certificate should appear on the VMware NSX-ALB.
  - _tenant_: The name of the tenant on the VMware NSX-ALB.

The keystore property definitions are used to render the TLS Protect Cloud user interface Certificate Information. The values provided are included in the request document.
![alt text](images/Keystore.png)

- ___certificateBundle___: a node within the domainSchema node defined by Venafi and contains the certificate, private key, and the issuing certificates.  This node must be defined as:
```json
  "certificateBundle": {
    "properties": {
        "certificate": {
            "contentEncoding": "base64",
            "type": "string"
        },
        "certificateChain": {
            "contentEncoding": "base64",
            "type": "string"
        },
        "privateKey": {
            "contentEncoding": "base64",
            "type": "string",
            "x-encrypted-base64": true
        }
    },
    "required": [
        "certificate",
        "privateKey",
        "certificateChain"
    ],
    "type": "object"
  }
```

> **_NOTE_**: The data in the certificate, certificateChain, and privateKey fields are managed by TLS Protect Cloud and the Venafi Satellite.  The data is transported to the Venafi Satellite as Base64 strings of the encrypted content.  The encrypted content is generated using the Venafi Satellite's unique data encryption key.  When an installation request is performed, the content is decrypted by the Venafi Satellite and sent to the machine connector as the ASN.1 der data.

The installCertificateBundle operation request includes the connection, keystore, and certificateBundle as defined in the manifest.json file:
```json
{
  "connection": {
    "credentialType": "local",
    "hostnameOrAddress": "sample.io",
    "password": "something",
    "port": 443,
    "username": "user"
  },
  "certificateBundle": {
    "certificate": "...",
    "certificateChain": "...",
    "privateKey": "..."
  },
  "keystore": {
    "certificateName": "Sample",
    "tenant": "Venafi"
  }
}
```

The machine connector response for a successful installCertificateBundle operation may include a JSON document.  This response is included in the configureInstallationEndpoint operation request body.  In this sample connector, the response to a successful installation operation is to the keystore data:
```json
{
  "keystore": {
    "certificateName": "Sample",
    "tenant": "Venafi"
  }
}
```

> **_NOTE_**: As the response is added to the configureInstallationEndpoint request, the top-level node name must **NOT** be either "connection" or "binding".

The response JSON document may contain any data the developer chooses.  No validation of the data is performed as the document is simply added to the configureInstallationEndpoint request.

## Configuring Usage of an installed Certificate, Private Key, and Issuing Chain
The second part of a provisioning operation is initiated after the machine connector successfully completes an installCertificateBundle operation.

In this sample connector, the configureInstallationEndpoint operation is used to configure a virtual service to use the newly installed certificate, private key, and the issuing certificate chain.
- ___binding___: a node within the domainSchema, defining the properties needed to determine how a certificate, private-key, and the issuing certificate chain are consumed on the device host.  In this machine connector, the property definitions are:
  - _virtualServiceName_: the name of the virtual service on the VMware AVI to be configured.

The binding property definitions are used to render the TLS Protect Cloud user interface Installation Endpoint. The values provided are included in the request document.

![alt text](images/Binding.png)


The configureInstallationEndpoint operation request includes the connection and binding fields as defined in the manifest.json file.  The request will also include any JSON document in response to the installation request.
```json
  "binding": {
    "virtualServiceName": "Sample Service"
  },
  "connection": {
    "credentialType": "local",
    "hostnameOrAddress": "sample.io",
    "password": "something",
    "port": 443,
    "username": "user"
  },
  "keystore": {
    "certificateName": "Sample",
    "tenant": "Venafi"
  }
```

> **_NOTE_**: The response for a successful configuration operation should have no content.

# Discovery Connector Basics
A machine connector may optionally support the discovery operation.

The provisioning operation request includes a certificate, private key, the issuing certificate chain, keystore data and the binding data to indicate where and how the certificate is used by the device.

The discovery operation is used to capture a certificate, it's issuing certificate chain, and a collection of one or more JSON documents with keystore and binding nodes showing where and how the certificate is being used.

> **_NOTE_**: The discovered certificates private key should **NOT** be included in a discovery response.

## Pagination
The discovery operation supports pagination to handle large certificates that may be present on a device.  The fixed discoveryPage node definition in the manifests domainSchema node must be defined as:
```json
  "discoveryPage": {
      "properties": {
          "discoveryType": {
              "type": "string"
          },
          "paginator": {
              "type": "string"
          }
      },
      "type": "object"
  }
```

Both the discoveryType and paginator strings are optional and the content of the string values are determined by the machine connector.

The discoveryPage is used to identify the start, continuation, and completion of a discovery operation.
- _start_: the request will NOT include a discoveryPage value.
- _continuation_: if a discovery cannot be completed while processing the request, then the machine connector can create a discoveryPage document and include it in the response.  When a discovery response includes a discoveryPage then that value is included in the next discovery request to the machine connector.
- _completion_: when a discovery is completed while processing the request, then the machine connector should NOT include a discoveryPage in the response.

In this sample machine connector, the value for discoveryType is the name of the tenant that was being processed, and the paginator value is the marshaled JSON of a data structure used to track the page and index of the certificates associated with that tenant.
```go
type certificateDiscoveryPaginator struct {
	Page  int `json:"page"`
	Index int `json:"index"`
}
```

The fixed discoveryControl node definition in the manifests domainSchema node must be defined as:
```json
  "discoveryControl": {
      "properties": {
          "maxResults": {
              "type": "int"
          }
      },
      "required": [
          "maxResults"
      ],
      "type": "object"
  }
```

The maxResults property indicates the maximum number of certificates that should be included in the response to the request.

## Request
- _discovery_: a required node within the domainSchema, defining the properties needed to configure how a certificate is performed on the device host. In this machine connector, the property definitions are:
```json
  "discovery": {
    "properties": {
      "excludeExpiredCertificates": {
        "type": "boolean",
        "x-labelLocalizationKey": "discovery.expiredCertificatesLabel",
        "x-rank": 1
      },
      "excludeInactiveCertificates": {
        "type": "boolean",
        "x-labelLocalizationKey": "discovery.excludeInactiveCertificates",
        "x-rank": 2
      },
      "tenants": {
        "default": "Common",
        "description": "discovery.tenantsDescription",
        "maxLength": 64,
        "type": "string",
        "x-labelLocalizationKey": "discovery.tenantsLabel",
        "x-rank": 0
      }
    },
    "type": "object"
  },
```

The discovery property definitions are used to render the discovery configuration within the TLS Protect Cloud user interface.  The values provided are included in the discovery operation request document.

![alt text](images/Discovery%20Configuration.png)

The request document will also include the connection and discoveryControl data.  When a discovery operation response includes a discoveryPage (indicating that the discovery operation is not complete), then the value is included in the next discovery operation request.
```json
{
  "connection": {
    "credentialType": "local",
    "hostnameOrAddress": "sample.io",
    "password": "something",
    "port": 443,
    "username": "user"
  },
  "discovery": {
    "excludeExpiredCertificates": false,
    "excludeInactiveCertificates": true,
    "tenants": "Venafi Engineering,Venafi Professional Services"
  },
  "discoveryControl": {
    "maxResults": 50
  }
}
```

### Response
The discovery operation response document is a JSON file with a "_messages_" collection and, optionally, a discoveryPage.

The messages collection contains one, but not more than maxResults, JSON documents representing a certificate found on the device.  The document must include:
- certificate: a string value containing a PEM encoded certificate.
- certificateChain: a collection of string values containing each of the issuing certificates as a PEM encoded certificate.
- machineIdentities: a collection of JSON files containing ...

```json
{
  "discoveryPage": {
    "discoveryType": "Venafi Engineering",
    "paginator": "{\"page\":3,\"index\":7}"
  },
  "messages": [
    {
      "certificate": "",
      "certificateChain": [
        "...",
        "..."
      ],
      "machineIdentities": [
        {
          "keystore": {
            "certificateName": "Sample 1",
            "tenant": "Venafi"
          },
          "binding": {
            "virtualServiceName": "Sample Service Alpha"
          }
        },
        {
          "keystore": {
            "certificateName": "Sample 2",
            "tenant": "Venafi"
          },
          "binding": {
            "virtualServiceName": "Sample Service Beta"
          }
        }
      ]
    }
  ]
}
```

# Code
The application's main function can be found in cmd/vmware-avi-connector/main.go.  The function calls the cmd/vmware-avi-connector/app/app.go ***New()*** function.

The applications REST API handlers can be found in the internal/handler/web/web.go file.  The WebhookService interface is implemented by the WebhookServiceImpl defined in internal/app/vmware-avi/vmware_avi.go.  The REST API handlers use those implementations to fulfill each machine connector provisioning and discovery operations.

The data structures that match the definitions in the manifest domainSchema can be found in the internal/app/domain subdirectory.  The JSON annotations define the field names and must match the property names in the corresponding manifest.json properties definitions.
- certificate_bundle.go
- connection.go
- keystore.go
- binding.go

The code implementing the logic for the machine connector provisioning operations can be found in internal/app/vmware-avi:
- test_connection.go
- install.go
- configure.go

The code implementing the logic for the machine connector discovery operation can be found in internal/app/discovery:
- discovery.go.

Comments in the aforementioned source code files describe both the common code that can be used by most machine connectors and the code that is specific to interacting with a VMware AVI host.

# Building
This machine connector includes a Makefile with targets for building the application.  This container image can be stored in your container registry to generate the final manifest file for creating or updating a connector. 

Some of the Makefile targets are:
- **help**: show available make targets
- **build**: create an executable binary that can be executed in a container run within a vSatellite.  The target operating system is Linux and the architecture will be AMD64.
- **test**: run the tests defined within the machine connector source code.
- **image**: will use the included build/Dockerfile to create a container image.
- **push**: will use the included build/Dockerfile to create a container image and push the image to your container registry.
- **manifests**: will use the manifest.json file to create:
  - **manifest.create.json**: is an updated manifest.json file that includes the container registry image path.  The file content can be used to create a new machine connector for a tenant in TLS Protect Cloud.
  - **manifest.update.json**: is an updated manifest.json file that includes the container registry image path.  The file content can be used to update an existing machine connector for a tenant in TLS Protect Cloud.

> **_NOTE_**: The API documentation for managing tenant machine connectors can be found on [Venafi Dev Central](https://developer.venafi.com/tlsprotectcloud/reference/post-v1-plugins)

> **_NOTE_**: You can use the TAG environment variable to override the default container image tag value of 'latest'.

You can chain the targets together to clean, build, and push in a single command:

```text
vmware-avi-connector % CONTAINER_REGISTRY=sample.io/dev-local TAG=demo make clean build push
go mod download
go generate github.com/venafi/vmware-avi-connector/...
mkdir -p output/bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o output/bin/vmware-avi-connector ./cmd/vmware-avi-connector/main.go
docker --context=default buildx build --output type=image,name=sample.io/dev-local/tls-protect-vmware-avi-connector:demo,push=true --metadata-file=buildx-digest.json \
                --target image \
                --file build/Dockerfile \
                 \
                --platform=linux/amd64 \
                --builder default .
[+] Building 3.2s (9/9) FINISHED                                                                                                                                                                                                                                                                         docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                                                                                                                                               0.0s
 => => transferring dockerfile: 354B                                                                                                                                                                                                                                                                               0.0s
 => [internal] load metadata for gcr.io/distroless/static-debian11@sha256:8ad6f3ec70dad966479b9fb48da991138c72ba969859098ec689d1450c2e6c97                                                                                                                                                                         0.0s
 => [internal] load .dockerignore                                                                                                                                                                                                                                                                                  0.0s
 => => transferring context: 2B                                                                                                                                                                                                                                                                                    0.0s
 => [1/3] FROM gcr.io/distroless/static-debian11@sha256:8ad6f3ec70dad966479b9fb48da991138c72ba969859098ec689d1450c2e6c97                                                                                                                                                                                           0.0s
 => [internal] load build context                                                                                                                                                                                                                                                                                  0.1s
 => => transferring context: 11.65MB                                                                                                                                                                                                                                                                               0.1s
 => CACHED [2/3] COPY output/bin/vmware-avi-connector /bin                                                                                                                                                                                                                                                         0.0s
 => CACHED [3/3] COPY manifest.json /bin                                                                                                                                                                                                                                                                           0.0s
 => exporting to image                                                                                                                                                                                                                                                                                             0.0s
 => => exporting layers                                                                                                                                                                                                                                                                                            0.0s
 => => writing image sha256:94cdc318e7df9d7a3e62993d407104cef779d8e753bcc9922b9aef75f3d00c99                                                                                                                                                                                                                       0.0s
 => => naming to sample.io/dev-local/tls-protect-vmware-avi-connector:demo                                                                                                                                                                                                       0.0s
 => pushing sample.io/dev-local/tls-protect-vmware-avi-connector:demo with docker                                                                                                                                                                                                1.7s
 => => pushing layer 5ae95b28c6a6                                                                                                                                                                                                                                                                                  1.4s
 => => pushing layer 39f83f69b805                                                                                                                                                                                                                                                                                  1.4s
 => => pushing layer 5b1fa8e3e100                                                                                                                                                                                                                                                                                  1.4s

View build details: docker-desktop://dashboard/build/default/default/4av1qc89o68z7pe5rhlbnxj4q
vmware-avi-connector %
```

# Testing
To test the machine connector operations, you can POST requests to the endpoints defined in the manifest.json hooks.mapping definition.  These endpoints must match those registered in the internal/handler/web/web.go RegisterHandlers function.

The body for POST must be a JSON document that matches the corresponding operations request structure.  For example, in this machine connector the hook.mapping path for ___testconnection___ is "/v1/testconnection".  The registered handler is implemented in the internal/app/vmware-avi/test_connection.go HandleTestConnection function.  The request structure for test connection is TestConnectionRequest:
```go
type TestConnectionRequest struct {
	Connection *domain.Connection `json:"connection"`
}
```

The Connection structure definition can be found in internal/app/domain/connection.go:

```go
type Connection struct {
	HostnameOrAddress string `json:"hostnameOrAddress"`
	Password          string `json:"password"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
}
```

The manifest.json connection node defines the properties hostnameOrAddress, password, port and username.

The "/v1/testconnection" body would then be:
```json
{
  "connection": {
    "hostnameOrAddress": "127.0.0.1",
    "password": "myPassword",
    "username": "sampler"
  }
}
```

> **_Note_**: The request body must contain all fields for the properties marked as required.  In the above example, the manifest.json domainSchema connection node properties definition for _port_ is an optional field with a default value.  When omitted from a request, any property with a default should be validated or set by the machine connector code.

> **_Note_**: The field values in the body should not be encrypted.  When this sample machine connector is run, a decryption middleware is added, which decrypts the body of a request if the data encryption key pair is present. When running locally, no key pair is expected. When running in a Venafi Satellite, the encrypted body is decrypted by the middleware before being received by the handler function.

You can run the cmd/vmware-avi-connector/main.go main function in the debugger and set a breakpoint in internal/app/vmware-avi/test_connection.go HandleTestConnection function.  With the machine connector started you can send a POST operation to http://localhost:8080/v1/testconnection.  The web server is started by a machine connector.

> **_Note_**: The content-type header should have a value of application/json.

# Deployment

When you have completed creating and testing your machine connector, you can deploy it exclusively in your TLS Protect Cloud production environment. With a tenant-specific connector, tenants can develop their own personal connectors (that are inaccessible by other tenants). This gives you the confidence to ensure your connectors work properly in a production environment before you release them to your customers. For details, see the [Integrate connector into tenant environment](https://developer.venafi.com/tlsprotectcloud/docs/integrate-connector-into-tenant-environment) guide.

To generate the final manifests for deployment to TLS Protect Cloud you can use ___make manifests___.  The manifests target will use the ___build___ and ___image___ targets to build the executable and the image.

To Create a machine connector for your tenant you can use the [Create a local plugin](https://developer.venafi.com/tlsprotectcloud/reference/post-v1-plugins) REST API.  The body of the request should be the manifest.create.json.  Once the new machine connector has been created it will be assigned a persistent unique ID.

To Update an existing machine connector for your tenant you can use the [Update a local plugin](https://developer.venafi.com/tlsprotectcloud/reference/patch-v1-plugins-id) REST API.  The ID in the path should be the ID assigned when the machine connector was created.

Additionally, you can use the [Disable a local plugin](https://developer.venafi.com/tlsprotectcloud/reference/post-v1-plugins-id-exclusions) REST API to flag the machine connector as disabled.  Disabling a machine connector prevents new machines from being created using the disabled machine connector.  This can be useful to deploy your plugin, create one, or more, machine instances for testing, and then disable the machine connector to prevent additional machines from being created during production testing.  You can use the [Remove plugin disablement](https://developer.venafi.com/tlsprotectcloud/reference/delete-v1-plugins-id-exclusions) REST API to re-enable your machine connector to create new machines.

Finally, you can use the [Delete a local plugin](https://developer.venafi.com/tlsprotectcloud/reference/delete-v1-plugins-id) REST API to remove the machine connector from your TLS Protect Cloud tenant.  This API can only be used once all machines associated with the machine connector have been deleted.

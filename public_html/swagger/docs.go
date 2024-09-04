// Package swagger Code generated by swaggo/swag. DO NOT EDIT
package swagger

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "https://www.trusted-platform.io/terms",
        "contact": {
            "name": "API Support",
            "url": "https://www.trusted-platform.io/support",
            "email": "support@trusted-platform.io"
        },
        "license": {
            "name": "Commercial",
            "url": "https://www.trusted-platform.io/licenses/commercial.txt"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/certificate": {
            "get": {
                "description": "Returns the server public RSA key",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "System"
                ],
                "summary": "Retrieve the server x509 certificate",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/config": {
            "get": {
                "security": [
                    {
                        "JWT": []
                    }
                ],
                "description": "Returns the server configuration",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "System"
                ],
                "summary": "System configuration",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/app.App"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/response.WebServiceResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/response.WebServiceResponse"
                        }
                    }
                }
            }
        },
        "/endpoints": {
            "get": {
                "description": "Returns a list of REST API endpoints",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "System"
                ],
                "summary": "REST API Endpoints",
                "responses": {
                    "200": {
                        "description": "OK"
                    }
                }
            }
        },
        "/events/{page}": {
            "get": {
                "security": [
                    {
                        "JWT": []
                    }
                ],
                "description": "Returns a page of system event log entries",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "System"
                ],
                "summary": "System Event Log",
                "parameters": [
                    {
                        "maxLength": 20,
                        "minLength": 1,
                        "type": "string",
                        "description": "string valid",
                        "name": "page",
                        "in": "path"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK"
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/response.WebServiceResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/response.WebServiceResponse"
                        }
                    }
                }
            }
        },
        "/login": {
            "post": {
                "description": "Authenticate a user and returns a new JWT",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Authentication"
                ],
                "summary": "Authenticate and obtain JWT",
                "parameters": [
                    {
                        "description": "UserCredentials struct",
                        "name": "UserCredentials",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/service.UserCredentials"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    }
                }
            }
        },
        "/login/refresh": {
            "get": {
                "security": [
                    {
                        "JWT": []
                    }
                ],
                "description": "Returns a new JWT token with a new, extended expiration date",
                "consumes": [
                    "application/json"
                ],
                "tags": [
                    "Authentication"
                ],
                "summary": "Refresh JWT",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/rest.JsonWebToken"
                        }
                    }
                }
            }
        },
        "/pubkey": {
            "get": {
                "description": "Returns the server public RSA key",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "System"
                ],
                "summary": "Retrieve the server pubilc key",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/status": {
            "get": {
                "security": [
                    {
                        "JWT": []
                    }
                ],
                "description": "Returns current system status metrics",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "System"
                ],
                "summary": "System Status",
                "responses": {
                    "200": {
                        "description": "OK"
                    }
                }
            }
        }
    },
    "definitions": {
        "app.App": {
            "type": "object",
            "properties": {
                "argon2": {
                    "$ref": "#/definitions/argon2.Argon2Config"
                },
                "attestation": {
                    "$ref": "#/definitions/config.Attestation"
                },
                "certificate_authority": {
                    "$ref": "#/definitions/ca.Config"
                },
                "config_dir": {
                    "type": "string"
                },
                "debug": {
                    "type": "boolean"
                },
                "debug-secrets": {
                    "type": "boolean"
                },
                "domain": {
                    "type": "string"
                },
                "hostmaster": {
                    "type": "string"
                },
                "hostname": {
                    "type": "string"
                },
                "listen": {
                    "type": "string"
                },
                "log_dir": {
                    "type": "string"
                },
                "platform_dir": {
                    "type": "string"
                },
                "runtime_user": {
                    "type": "string"
                },
                "tpm": {
                    "$ref": "#/definitions/tpm2.Config"
                },
                "webservice": {
                    "$ref": "#/definitions/config.WebService"
                }
            }
        },
        "argon2.Argon2Config": {
            "type": "object",
            "properties": {
                "iterations": {
                    "type": "integer"
                },
                "keyLen": {
                    "type": "integer"
                },
                "memory": {
                    "type": "integer"
                },
                "parallelism": {
                    "type": "integer"
                },
                "saltLen": {
                    "type": "integer"
                }
            }
        },
        "ca.Config": {
            "type": "object",
            "properties": {
                "auto_import_issuing_ca": {
                    "type": "boolean"
                },
                "default_idevid_cn": {
                    "type": "string"
                },
                "default_validity": {
                    "type": "integer"
                },
                "identity": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/ca.Identity"
                    }
                },
                "platform_ca": {
                    "type": "integer"
                },
                "require-password": {
                    "type": "boolean"
                },
                "sans_include_localhost": {
                    "type": "boolean"
                },
                "system_cert_pool": {
                    "type": "boolean"
                }
            }
        },
        "ca.Identity": {
            "type": "object",
            "properties": {
                "keys": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/keystore.KeyConfig"
                    }
                },
                "keystores": {
                    "$ref": "#/definitions/platform.KeyChainConfig"
                },
                "sans": {
                    "$ref": "#/definitions/ca.SubjectAlternativeNames"
                },
                "subject": {
                    "$ref": "#/definitions/ca.Subject"
                },
                "valid": {
                    "type": "integer"
                }
            }
        },
        "ca.Subject": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string"
                },
                "cn": {
                    "type": "string"
                },
                "country": {
                    "type": "string"
                },
                "locality": {
                    "type": "string"
                },
                "organization": {
                    "type": "string"
                },
                "organizational_unit": {
                    "type": "string"
                },
                "postal_code": {
                    "type": "string"
                },
                "province": {
                    "type": "string"
                }
            }
        },
        "ca.SubjectAlternativeNames": {
            "type": "object",
            "properties": {
                "dns": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "email": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "ips": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            }
        },
        "config.Attestation": {
            "type": "object",
            "properties": {
                "allow-open-enrollment": {
                    "type": "boolean"
                },
                "allow_attestor_self_ca": {
                    "type": "boolean"
                },
                "allowed_verifiers": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "client_ca_cert": {
                    "type": "string"
                },
                "insecure_port": {
                    "type": "integer"
                },
                "insecure_skip_verify": {
                    "type": "boolean"
                },
                "quote-pcrs": {
                    "type": "array",
                    "items": {
                        "type": "integer"
                    }
                },
                "tls_port": {
                    "type": "integer"
                }
            }
        },
        "config.Identity": {
            "type": "object",
            "properties": {
                "sans": {
                    "$ref": "#/definitions/ca.SubjectAlternativeNames"
                },
                "subject": {
                    "$ref": "#/definitions/ca.Subject"
                },
                "valid": {
                    "type": "integer"
                }
            }
        },
        "config.WebService": {
            "type": "object",
            "properties": {
                "certificate": {
                    "$ref": "#/definitions/config.Identity"
                },
                "home": {
                    "type": "string"
                },
                "jwt_expiration": {
                    "type": "integer"
                },
                "key": {
                    "$ref": "#/definitions/keystore.KeyConfig"
                },
                "port": {
                    "type": "integer"
                },
                "tls_port": {
                    "type": "integer"
                }
            }
        },
        "keystore.ECCConfig": {
            "type": "object",
            "properties": {
                "curve": {
                    "type": "string"
                }
            }
        },
        "keystore.KeyConfig": {
            "type": "object",
            "properties": {
                "algorithm": {
                    "type": "string"
                },
                "cn": {
                    "type": "string"
                },
                "debug": {
                    "type": "boolean"
                },
                "default": {
                    "type": "boolean"
                },
                "ecc": {
                    "$ref": "#/definitions/keystore.ECCConfig"
                },
                "hash": {
                    "type": "string"
                },
                "parent": {
                    "$ref": "#/definitions/keystore.KeyConfig"
                },
                "password": {
                    "type": "string"
                },
                "platform-policy": {
                    "type": "boolean"
                },
                "rsa": {
                    "$ref": "#/definitions/keystore.RSAConfig"
                },
                "secret": {
                    "type": "string"
                },
                "signature-algorithm": {
                    "type": "string"
                },
                "store": {
                    "type": "string"
                }
            }
        },
        "keystore.RSAConfig": {
            "type": "object",
            "properties": {
                "size": {
                    "type": "integer"
                }
            }
        },
        "pkcs11.Config": {
            "type": "object",
            "properties": {
                "cn": {
                    "type": "string"
                },
                "config": {
                    "type": "string"
                },
                "label": {
                    "type": "string"
                },
                "library": {
                    "type": "string"
                },
                "pin": {
                    "type": "string"
                },
                "platform_policy": {
                    "type": "boolean"
                },
                "slot": {
                    "type": "integer"
                },
                "so_pin": {
                    "type": "string"
                }
            }
        },
        "pkcs8.Config": {
            "type": "object",
            "properties": {
                "cn": {
                    "type": "string"
                },
                "platform_policy": {
                    "type": "boolean"
                }
            }
        },
        "platform.KeyChainConfig": {
            "type": "object",
            "properties": {
                "cn": {
                    "type": "string"
                },
                "pkcs11": {
                    "$ref": "#/definitions/pkcs11.Config"
                },
                "pkcs8": {
                    "$ref": "#/definitions/pkcs8.Config"
                },
                "tpm2": {
                    "$ref": "#/definitions/tpm2.KeyStoreConfig"
                }
            }
        },
        "response.WebServiceResponse": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "integer"
                },
                "error": {
                    "type": "string"
                },
                "payload": {},
                "success": {
                    "type": "boolean"
                }
            }
        },
        "rest.JsonWebToken": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string"
                },
                "token": {
                    "type": "string"
                }
            }
        },
        "service.UserCredentials": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                }
            }
        },
        "tpm2.Config": {
            "type": "object",
            "properties": {
                "device": {
                    "type": "string"
                },
                "ek": {
                    "$ref": "#/definitions/tpm2.EKConfig"
                },
                "encrypt_sessions": {
                    "type": "boolean"
                },
                "entropy": {
                    "type": "boolean"
                },
                "file_integrity": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "hash": {
                    "type": "string"
                },
                "iak": {
                    "$ref": "#/definitions/tpm2.IAKConfig"
                },
                "idevid": {
                    "$ref": "#/definitions/tpm2.IDevIDConfig"
                },
                "keystore": {
                    "$ref": "#/definitions/tpm2.KeyStoreConfig"
                },
                "lockout-auth": {
                    "type": "string"
                },
                "platform_pcr": {
                    "type": "integer"
                },
                "simulator": {
                    "type": "boolean"
                },
                "ssrk": {
                    "$ref": "#/definitions/tpm2.SRKConfig"
                }
            }
        },
        "tpm2.EKConfig": {
            "type": "object",
            "properties": {
                "_platform_policy": {
                    "type": "boolean"
                },
                "algorithm": {
                    "type": "string"
                },
                "cert-handle": {
                    "type": "integer"
                },
                "cn": {
                    "type": "string"
                },
                "debug": {
                    "type": "boolean"
                },
                "ecc": {
                    "$ref": "#/definitions/keystore.ECCConfig"
                },
                "handle": {
                    "type": "integer"
                },
                "hierarchy_auth": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                },
                "rsa": {
                    "$ref": "#/definitions/keystore.RSAConfig"
                }
            }
        },
        "tpm2.IAKConfig": {
            "type": "object",
            "properties": {
                "_platform_policy": {
                    "type": "boolean"
                },
                "algorithm": {
                    "type": "string"
                },
                "cert-handle": {
                    "type": "integer"
                },
                "cn": {
                    "type": "string"
                },
                "debug": {
                    "type": "boolean"
                },
                "ecc": {
                    "$ref": "#/definitions/keystore.ECCConfig"
                },
                "handle": {
                    "type": "integer"
                },
                "hash": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                },
                "rsa": {
                    "$ref": "#/definitions/keystore.RSAConfig"
                },
                "signature-algorithm": {
                    "type": "string"
                }
            }
        },
        "tpm2.IDevIDConfig": {
            "type": "object",
            "properties": {
                "_platform_policy": {
                    "type": "boolean"
                },
                "algorithm": {
                    "type": "string"
                },
                "cert-handle": {
                    "type": "integer"
                },
                "cn": {
                    "type": "string"
                },
                "debug": {
                    "type": "boolean"
                },
                "ecc": {
                    "$ref": "#/definitions/keystore.ECCConfig"
                },
                "handle": {
                    "type": "integer"
                },
                "hash": {
                    "type": "string"
                },
                "model": {
                    "type": "string"
                },
                "pad": {
                    "type": "boolean"
                },
                "password": {
                    "type": "string"
                },
                "rsa": {
                    "$ref": "#/definitions/keystore.RSAConfig"
                },
                "serial": {
                    "type": "string"
                },
                "signature-algorithm": {
                    "type": "string"
                }
            }
        },
        "tpm2.KeyStoreConfig": {
            "type": "object",
            "properties": {
                "cn": {
                    "type": "string"
                },
                "platform_policy": {
                    "type": "boolean"
                },
                "srk-handle": {
                    "type": "integer"
                },
                "srk_auth": {
                    "type": "string"
                }
            }
        },
        "tpm2.SRKConfig": {
            "type": "object",
            "properties": {
                "_platform_policy": {
                    "type": "boolean"
                },
                "algorithm": {
                    "type": "string"
                },
                "cn": {
                    "type": "string"
                },
                "debug": {
                    "type": "boolean"
                },
                "ecc": {
                    "$ref": "#/definitions/keystore.ECCConfig"
                },
                "handle": {
                    "type": "integer"
                },
                "hierarchy-auth": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                },
                "rsa": {
                    "$ref": "#/definitions/keystore.RSAConfig"
                }
            }
        }
    },
    "securityDefinitions": {
        "JWT": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "v0.0.1",
	Host:             "localhost:8443",
	BasePath:         "/api/v1",
	Schemes:          []string{},
	Title:            "Trusted Platform",
	Description:      "The Trusted Platform RESTful Web Services API",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}

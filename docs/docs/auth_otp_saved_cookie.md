---
id: auth_otp_saved_cookie
title: How to easliy setup OTP and session persistence authentication on your site
sidebar_label: Setup OTP and Session Persistence
---

# How to easliy setup OTP and session persistence authentication on your site

## Authentication Initialization
```
curl -v http://localhost:8080/gortas/auth/v1/default/otp
```

### Receiving Credentials Request

```json
{
    "flowId": "0000-0000-0000-0000",
    "module": "phone",
    "credentials": {
        "phone": {
            "type":"text",
            "validation": "^\\d{5,16}$",
            "required": true
        }
    }
}
```

## Sending Credentials with Phone number

```json
{
    "flowId": "0000-0000-0000-0000",
    "module": "phone",
    "credentials": {
        "phone": {
            "value": "55512345678"
        }
    }
}
```
## Phone Response

### Phone Error

```json
{
    "flowId": "0000-0000-0000-0000",
    "module": "phone",
    "credentials": {
        "phone": {
            "type":"text",
            "validation": "^\\d{5,16}$",
            "required": true,
            "message": "Error sending OTP", 
        }
    }
}
```
### OTP Credential Request

```json
{
    "flowId": "0000-0000-0000-0000",
    "module": "otp",
    "credentials": {
        "otp": {
            "type":"text",
            "required": true,
            "additionalProperties": {
                "timeoutSec": 3600,
                "resendAfterSec": 1800,
                "retres": 3,
            }
        },
        "action": {
            "type": "options",
            "required": false,
            "additionalPropertues": {
                "values": ["check", "send"],
                "default": "check",
            }
        }
    }
}
```

## OTP Credentials Response

```json
{
    "flowId": "0000-0000-0000-0000",
    "stage": "otp",
    "credentials": {
        "otp": {
            "value" : "1234",
        },
        "action": {
            "value": "check"
        }
    }
}
```

### Invalid OTP

```json
{
    "flowId": "0000-0000-0000-0000",
    "module": "otp",
    "credentials": {
        "otp": {
            "type":"text",
            "required": true,
            "message": "Invalid OTP", 
            "additionalProperties": {
                "timeoutSec": 3600,
                "resendAfterSec": 1800,
                 "retres": 2,
            }
        },
        "action": {
            "type": "options",
            "required": false,
            "additionalPropertues": {
                "values": ["check", "send"],
                "default": "check",
            }
        }
    }
}
```

### Valid OTP

```json
{
    "sessionId": "1234-1234-1234-1234"
}
```

## Set Session Persistence
Set-Cookie: Gortas-Persistence "123123123-123123123-123123123-123123123-1231231"
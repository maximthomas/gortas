# Gortas
**Gortas** (Golang Authentication Service) is a flexible API based authentication service, allows adding authentication to your site or service with minimum effort. 
**Gortas** supports multiple authentication methods across various data sources. You can authenticate against your Active Directory or other LDAP user directory or MongoDB.

It allows building complex authentication processes with various steps and different authentication methods.   

For example, you can build login and password authentication with an SMS confirmation code

## Deeper Into the Details

### Supported Authentication methods
* Username and password - authenticates against an existing user datastore
* Registration - creates a user account in a user data store for further authentication
* Kerberos - uses Kerberos authentication
* OTP - one-time password sent via email or SMS

It is possible to develop custom authentication methods.

### Supported Data Sources
* LDAP
* NoSQL
  * MongoDB
* SQL databases (in development)

## Main concepts

With **Gortas** you can build an authentication system with any desired complexity across different data sources simultaneously.

### Realm

There could be different realms in Gortas - for example, the `staff` realm for employees and the `clients` realm for clients.
All realms use their own user data stores. For example, for staff users, we will use an enterprise LDAP user directory, for clients we could use another database, for example, MongoDB.
Every realm contains authentication modules, authentication chains, and user data store.

### Authentication Module

Single authentication module, responsible for authentication or authorization step.
For example - prompt username and password or send and verify a one-time password.

### Authentication FLow

Authentication modules are organized in flows.
Every authentication chain is a sequence of authentication modules to orchestrate complex authentication processes.
For example, we have two modules: Login module - prompts a user to provide login and password, and OTP module - sends SMS with a one-time password to the user.

When a user tries to authenticate he will be prompted to enter login and password.
If the credentials are correct authentication service sends OTP via SMS and prompts the user to enter the one-time password as a second authentication factor.
On the other hand, we can line up Kerberos and login and password in the same chain.
So if a user was not authenticated in Kerberos automatically, he will be prompted for username and password

## Quick Start with docker-compose

Clone **Gortas** repository

```
git clone https://github.com/maximthomas/gortas.git
```

Then go to `gortas` directory and run `docker-compose`

```
docker-compose up
```

This command will create services:
1. `gortas` - authentication API service
1. `mongo` - Mongo database for user and session storage

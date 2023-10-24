# Autenticami AuthZ

[![Documentation](https://img.shields.io/website?label=Docs&url=https%3A%2F%2Fdocs.autenticami.com%2F)](https://docs.autenticami.com/)
[![AutenticamiCI](https://github.com/autenticami/autenticami-authz/actions/workflows/autenticami-ci.yml/badge.svg)](https://github.com/autenticami/autenticami-authz/actions/workflows/autenticami-ci.yml)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=autenticami_autenticami-authz&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=autenticami_autenticami-authz) 
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=autenticami_autenticami-authz&metric=bugs)](https://sonarcloud.io/summary/new_code?id=autenticami_autenticami-authz)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=autenticami_autenticami-authz&metric=coverage)](https://sonarcloud.io/summary/new_code?id=autenticami_autenticami-authz)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=autenticami_autenticami-authz&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=autenticami_autenticami-authz) 
[![Go Report Card](https://goreportcard.com/badge/github.com/autenticami/autenticami-authz)](https://goreportcard.com/report/github.com/autenticami/autenticami-authz)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=autenticami_autenticami-authz&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=autenticami_autenticami-authz) 
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=autenticami_autenticami-authz&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=autenticami_autenticami-authz) 

<img src="assets/images/autenticami-black-logo.png" width="250px" height="auto"/>


`Autenticami` is a multi-account `Identity and Access Management` (IAM or IdAM) solution to enable a modern identity-based access control.

As an `Autenticami administrator` you can create multiple accounts and create multiple projects within each account.

All you have to do is describe your project's `resources` within your account and create your own access control policies. Resources are organized into project's domains.

`Autenticami` allows to specify who or what can access resources by the means of fine-grained permissions:

- `Who`: *Identities (Users and Roles) authenticated in the application*
- `Can Access`: *Permissions granted by attaching policies*
- `Resources`: *Resources targeted by permissions*

To enforce the access control process, the application implements the Policy Enforcement Point using the available SDKs

Below is a sample policy document for granting access to the Employee and Timesheet resources of an HR project (hr-app):

```json linenums="1"
{
  "Syntax": "autenticami1",
  "Name": "person-base-reader",
  "Type": "ACL",
  "Permit": [
    {
      "Name": "permit-hr/person/reader/any",
      "Actions": [
        "person:ListEmployee",
        "person:ReadEmployee"
      ],
      "Resources": [
        "uur:581616507495:default:hr-app:organisation:person/*"
      ]
    },
    {
      "Name": "permit-hr/timesheet/writer/any",
      "Actions": [
        "person:ReadTimesheet",
        "person:CreateTimesheet",
        "person:UpdateTimesheet",
        "person:DeleteTimesheet"
      ],
      "Resources": [
        "uur:581616507495:default:hr-app:time-management:person/*"
      ]
    }
  ],
  "Forbid": [
    {
      "Name": "forbid-write-hr/timesheet/writer/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
      "Actions": [
        "time-management/person:Read"
      ],
      "Resources": [
        "uur:581616507495:default:hr-app:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2"
      ]
    }
  ]
}
```

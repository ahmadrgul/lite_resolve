# lite_resolve
LiteResolve: A lightweight and basic DNS client for resolving domain names
v1.0: Basic DNS client which uses GOOGLE's DNS Server behind the scenes to resolve record type A hostnames
v1.1: Refactored Code, Same functions 
v2.0: Added support for almost all the major dns query types including AAAA, PTR, CNAME, NS and MX. Decluttered the codebase, to make it more organized, maintainable and easy to extend. Still using recursive resolution using dns.google
# web2py-plugin-authman
**Authorization Management Plugin for web2py**

## Purpose

Simple plugin to provide interface to manage authorizations, roles (also known as groups), and users.

## Background

web2py has build-in authorization system, but uses direct manipulation of the respective tables via `database administration`.

This plugin extends the existing capabilities:

- Separate definition of Authorization
- Roles (groups) can contain other roles, providing the ability to reflect organizational structure
- Separation of duties
  - Definition of Authorization
  - Assignment of Authorization to Role(s)
  - Assignment of User(s) to Role(s)
  - Activation of Assignments and Authorization

## First Steps

1. Create role `root` and assign an user to it.

2. Navigate to `(app)/plugin_authman/` (User must have role ```root```).

   There should be a link **Initialize**.

   This will initialize the authorizations, roles and permissions for the plugin.

3. Return to `(app)/plugin_authman/` (User must have role ```root```).   

   There should be a link **Activate**.

   At this time the `root` role will have all permissions defined in authman. As long as the `root` role exists, it will have all permissions. This gets refreshed when any changes are activated. Removing the `root` role will disable this behavior.

4. Return to `(app)/plugin_authman/`.

   Users, Roles and Authorizations can be maintained now.

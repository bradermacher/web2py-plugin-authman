# -*- coding: utf-8 -*-

# tables to keep track of entries created in the 'real' auth tables to allow to remove/refresh
db.define_table('plugin_authman_owned_permission', Field('permission_id', type='integer'))
db.define_table('plugin_authman_owned_group', Field('group_id',      type='integer'))

# stores authorizations, used to grant permissions
# (c in fieldnames replaced with k to satisfy reserved words requirements)
# aktion (action) translates to auth_permission.name
# objekt (object) translates to auth_permission.table_name
# permission.record_id is set to 0
# act and obj together should be unique
db.define_table('plugin_authman_authorization',
                Field('aktion', required=True, notnull=True, label=T('Action')),
                Field('objekt', required=True, notnull=True, label=T('Object')),
                Field('description', type='text', label=T('Description')),
                format='%(aktion)s %(objekt)s')
db.plugin_authman_authorization.objekt.requires=IS_NOT_IN_DB(db(db.plugin_authman_authorization.aktion==request.vars.aktion), 'plugin_authman_authorization.objekt')

# stores roles, used to create entries in auth_group and granting permissions
# role translates to auth_group.role
# description trantates to auth_group.description
# role is unique (key is to long to use database unique restriction (unique=True)
db.define_table('plugin_authman_role',
                Field('role',        required=True, notnull=True, label=T('Role')),
                Field('description', type='text',                 label=T('Description')),
                format='%(role)s')
db.plugin_authman_role.role.requires=IS_NOT_IN_DB(db(db.plugin_authman_role), 'plugin_authman_role.role')

# stores permissions (combination of authorization and role)
# role_id and authorization_id together should be unique
db.define_table('plugin_authman_permission',
                Field('role_id', type='reference plugin_authman_role', required=True, notnull=True, label=T('Role')),
                Field('authorization_id', type='reference plugin_authman_authorization', required=True, notnull=True, label=T('Authorization')),
                format='%(role_id.role)s: %(authorization_id.aktion)s %(authorization_id.objekt)s')
db.plugin_authman_permission.authorization_id.requires=IS_NOT_IN_DB(db(db.plugin_authman_permission.role_id==request.vars.role_id), 'plugin_authman_permission.authorization_id')

# stores membership of a user in a role
# using weak reference (application level, not database) to minimize possible impact on existing systems
# using 'auth.settings' to support renamed auth tables
db.define_table('plugin_authman_membership',
                Field('user_id', type='integer', required=True, notnull=True, label=T('User')),
                Field('role_id', type='reference plugin_authman_role', required=True, notnull=True, label=T('Role')))
# supporting optional use of username "auth.define_tables(username=True)"
if 'username' in auth.settings.table_user.fields():
    db.plugin_authman_membership.user_id.requires=IS_IN_DB(db(auth.settings.table_user), 'auth_user.id', "%(username)s (%(first_name)s %(last_name)s)")
else:
    db.plugin_authman_membership.user_id.requires=IS_IN_DB(db(auth.settings.table_user), 'auth_user.id', "%(first_name)s %(last_name)s")
# reference definition does not automatically propagate
db.plugin_authman_membership.role_id.requires=IS_IN_DB(db(db.plugin_authman_role), 'plugin_authman_role.id', "%(role)s")

# stores included role(s)
# role_id and subrole_id together should be unique
db.define_table('plugin_authman_subrole',
                Field('role_id',    type='reference plugin_authman_role', required=True, notnull=True, label=T('Role')),
                Field('subrole_id', type='reference plugin_authman_role', required=True, notnull=True, label=T('Subrole')),
                format='%(role_id.role)s: %(subrole_id.role)s')
db.plugin_authman_subrole.subrole_id.requires=[IS_IN_DB(db(db.plugin_authman_role), 'plugin_authman_role.id', '%(role)s'),
        IS_NOT_IN_DB(db(db.plugin_authman_subrole.role_id==request.vars.role_id), 'plugin_authman_subrole.subrole_id')]

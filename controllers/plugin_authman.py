# -*- coding: utf-8 -*-

def index():
    # Read plugin description and display.
    # Some logic in view (status of plugin and authorization
    from os.path import join as pathjoin
    from gluon.contrib.markdown import WIKI as MARKDOWN
    with open(pathjoin(request.folder,'private', 'plugin_authman.README.md')) as f:
        data = f.read()
    return dict(data=MARKDOWN(data))

@auth.requires_permission('display', 'plugin_authman_authorization')
def authorization():
    db.plugin_authman_authorization.id.writable=db.plugin_authman_authorization.id.readable=False
    grid = SQLFORM.grid(db.plugin_authman_authorization,
                        orderby = db.plugin_authman_authorization.objekt|db.plugin_authman_authorization.aktion,
                        deletable=True if auth.has_permission('delete', 'plugin_authman_authorization') else False,
                        editable=True if auth.has_permission('edit', 'plugin_authman_authorization') else False,
                        create=True if auth.has_permission('create', 'plugin_authman_authorization') else False,
                        csv=False,
                        maxtextlength=500,
                        showbuttontext=False,
                       )
    return locals()

@auth.requires_permission('assign', 'plugin_authman_role')
def authorization_assign():
    # manage assignment of role to role
    if request.args(0) is None:
        redirect(URL('role'))
    r = db.plugin_authman_role(request.args(0, cast=int)) or redirect(URL('role'))
    # select all roles and the respective membership information
    rows = db().select(db.plugin_authman_authorization.ALL,
                       db.plugin_authman_permission.role_id,
                       left=db.plugin_authman_permission.on((db.plugin_authman_permission.authorization_id==db.plugin_authman_authorization.id)
                                                          & (db.plugin_authman_permission.role_id==r.id)),
                       orderby = db.plugin_authman_authorization.objekt|db.plugin_authman_authorization.aktion)
    data = []
    current = {}
    for row in rows:
        data.append(TR(TD(INPUT(_type='checkbox', _name='check%05u' % row.plugin_authman_authorization.id, value=False if row.plugin_authman_permission.role_id is None else True)),
                       TD(row.plugin_authman_authorization.aktion),
                       TD(row.plugin_authman_authorization.objekt),
                       TD(row.plugin_authman_authorization.description)))
        current[row.plugin_authman_authorization.id] = False if row.plugin_authman_permission.role_id is None else True
    session.current = current
    form = FORM(TABLE(data, _class="table table-striped"),INPUT(_type='submit', _value='Submit'))
    if form.accepts(request,session):
        for i in session.current.keys():
            if session.current[i]:
                if request.vars['check%05u' % i] is None:
                    db((db.plugin_authman_permission.role_id==r.id) & (db.plugin_authman_permission.authorization_id==i)).delete()
            else:
                if request.vars['check%05u' % i] == 'on':
                    db.plugin_authman_permission.insert(role_id=r.id, authorization_id=i)
        db.commit()
        session.flash = 'information updated'
        redirect(URL('authorization_assign', args=[r.id]))
    return dict(r=r, form=form)



@auth.requires_permission('activate', 'plugin_authman')
def activate():
    result = []
    # clear all owned permissions and groups
    result.extend(__delete_owned_permissions())
    result.extend(__delete_owned_groups())
    # grant all permissions to root
    root_id = auth.id_group('root')
    if root_id:
        for rcd in db(db.plugin_authman_authorization).select():
            __add_permission(root_id, rcd.aktion, rcd.objekt)
        result.append([700, 'Granted all permissions to root.'])
        db.commit()
    # create groups (roles)
    roles = {}
    for rcd in db(db.plugin_authman_role).select():
        roles[rcd.id]=__add_role(rcd.role, rcd.description)
        result.append([400, 'Added group "%s".' % rcd.role])
    result.append([700, 'Added roles defined in authman.'])
    db.commit()
    # grant permissions to roles
    for rcd in db(db.plugin_authman_permission).select(join=db.plugin_authman_authorization.on(db.plugin_authman_authorization.id==db.plugin_authman_permission.authorization_id)):
        __add_permission(roles[rcd.plugin_authman_permission.role_id], rcd.plugin_authman_authorization.aktion, rcd.plugin_authman_authorization.objekt)
    result.append([700, 'Granted defined permissions to respective roles.'])
    db.commit()
    # add membership to roles
    for rcd in db(db.plugin_authman_membership).select():
        for r in __get_contained_roles(rcd.role_id):
            auth.add_membership(roles[r], rcd.user_id)
    result.append([700, 'Added membership to roles.'])
    db.commit()
    return dict(result=result)

def test():
    children1 = __get_contained_roles(1)
    children5 = __get_contained_roles(5)
    rows = db(db.plugin_authman_subrole.role_id==5).select(db.plugin_authman_subrole.subrole_id)

    return locals()

@auth.requires_permission('deactivate', 'plugin_authman')
def deactivate():
    result = []
    # clear all owned permissions and groups
    result.extend(__delete_owned_permissions())
    result.extend(__delete_owned_groups())
    # seed permission table so that root can activate
    result.extend(__root_activation())
    return dict(result=result)

@auth.requires_membership('root')
def initialize():
    result = []
    if db(db.plugin_authman_authorization).isempty():
        from pickle import load
        from os.path import join as pathjoin
        from os import listdir
        authorization={}
        role={}
        for filename in listdir(pathjoin(request.folder, 'private')):
            if filename.endswith('authman.pickle'):
                picklefile = pathjoin(pathjoin(request.folder, 'private'), filename)
                with open(picklefile) as f:
                    data = load(f)
                    for i in data['plugin_authman_authorization']:
                        authorization['%(aktion)s|%(objekt)s' % i] = db.plugin_authman_authorization.insert(aktion=i['aktion'], objekt=i['objekt'], description=i['description'])
                        result.append([400, 'Added authorization "%(aktion)s %(objekt)s".' % i])
                    for i in data['plugin_authman_role']:
                        role[i['role']] = db.plugin_authman_role.insert(role=i['role'], description=i['description'])
                        result.append([400, 'Added role "%s".' % i['role']])
                        if i.has_key('plugin_authman_permission'):
                            for j in i['plugin_authman_permission']:
                                db.plugin_authman_permission.insert(role_id=role[i['role']], authorization_id=authorization['%(aktion)s|%(objekt)s' % j])
                                result.append([400, 'Granted "%s %s" to "%s".' % (j['aktion'], j['objekt'], i['role'])])
                        if i.has_key('plugin_authman_subrole'):
                            for j in i['plugin_authman_subrole']:
                                db.plugin_authman_subrole.insert(role_id=role[i['role']], subrole_id=role[j])
                                result.append([400, 'Added role "%s" to "%s".' % (j, i['role'])])
    else:
        result.append([700, 'Tables not empty. No entries added.'])
    # seed permission table so that root can activate
    result.extend(__root_activation())
    result.append([700, 'Authman initialization complete.'])
    return dict(result=result)

@auth.requires_permission('display', 'plugin_authman_role')
def role():
    # Hide id field
    db.plugin_authman_role.id.writable=db.plugin_authman_role.id.readable=False
    links=[]
    if auth.has_permission('assign', 'plugin_authman_role'):
        links.append({'header': '', 'body': lambda row: A(SPAN(_class="icon list icon-list glyphicon glyphicon-list"),
                                                         _class="button btn btn-default",
                                                         _title="Assignment to Roles",
                                                         _href=URL('role_assign', args=[row.id]))})
    if auth.has_permission('assign', 'plugin_authman_authorization'):
        links.append({'header': '', 'body': lambda row: A(SPAN(_class="icon list icon-list glyphicon glyphicon-list-alt"),
                                                         _class="button btn btn-default",
                                                         _title="Authorization Assignment",
                                                         _href=URL('authorization_assign', args=[row.id]))})
    grid = SQLFORM.grid(db.plugin_authman_role,
                        orderby = db.plugin_authman_role.role,
                        deletable=True if auth.has_permission('delete', 'plugin_authman_role') else False,
                        editable=True if auth.has_permission('edit', 'plugin_authman_role') else False,
                        create=True if auth.has_permission('create', 'plugin_authman_role') else False,
                        csv=False,
                        links=links,
                        maxtextlength=500,
                        showbuttontext=False,
                       )
    return locals()

@auth.requires_permission('assign', 'plugin_authman_role')
def role_assign():
    # manage assignment of role to role
    if request.args(0) is None:
        redirect(URL('role'))
    r = db.plugin_authman_role(request.args(0, cast=int)) or redirect(URL('role'))
    # to minimize circular references get list of role that contain this role
    parents = __get_containing_roles(r.id)
    parents.add(r.id)
    # select all roles and the respective membership information
    rows = db(~db.plugin_authman_role.id.belongs(parents)).select(db.plugin_authman_role.ALL,
                                                                  db.plugin_authman_subrole.role_id,
                                                                  left=db.plugin_authman_subrole.on((db.plugin_authman_subrole.subrole_id == db.plugin_authman_role.id) &
                                                                                                    (db.plugin_authman_subrole.role_id == r.id)),
                                                                  orderby=db.plugin_authman_role.role)
    data = []
    current = {}
    for row in rows:
        data.append(TR(TD(INPUT(_type='checkbox', _name='check%05u' % row.plugin_authman_role.id, value=False if row.plugin_authman_subrole.role_id is None else True)),
                       TD(row.plugin_authman_role.role),
                       TD(row.plugin_authman_role.description)))
        current[row.plugin_authman_role.id] = False if row.plugin_authman_subrole.role_id is None else True
    session.current = current
    form = FORM(TABLE(data, _class="table table-striped"),INPUT(_type='submit', _value='Submit'))
    if form.accepts(request,session):
        for i in session.current.keys():
            if session.current[i]:
                if request.vars['check%05u' % i] is None:
                    db((db.plugin_authman_subrole.role_id==r.id) & (db.plugin_authman_subrole.subrole_id==i)).delete()
            else:
                if request.vars['check%05u' % i] == 'on':
                    db.plugin_authman_subrole.insert(role_id=r.id, subrole_id=i)
        db.commit()
        session.flash = 'information updated'
        redirect(URL('role_assign', args=[r.id]))
    return dict(r=r, form=form)

@auth.requires_permission('display', 'plugin_authman_user')
def user():
    # Hide id field
    auth.settings.table_user.id.writable=auth.settings.table_user.id.readable=False
    # Restrict list to common fields
    fields = [auth.settings.table_user.first_name,
              auth.settings.table_user.last_name,
              auth.settings.table_user.email]
    # set default order to lastname, firstname
    orderby = auth.settings.table_user.last_name|auth.settings.table_user.first_name
    # add username field if it exits and user for initial order
    if 'username' in auth.settings.table_user.fields():
        fields.insert(0, auth.settings.table_user.username)
        orderby = auth.settings.table_user.username
    # provide addidional buttons
    links = [{'header': "Status", 'body': lambda row: __user_status(row)},]
    if auth.has_permission('assign', 'plugin_authman_user'):
        links.append({'header': '', 'body': lambda row: A(SPAN(_class="icon list icon-list glyphicon glyphicon-list"),
                                                          _class="button btn btn-default",
                                                          _title="Assignment to Roles",
                                                          _href=URL('user_assign', args=[row.id]))})
    grid = SQLFORM.grid(auth.settings.table_user,
                        fields=fields,
                        orderby = orderby,
                        deletable=False,
                        editable=True if auth.has_permission('edit', 'plugin_authman_user') else False,
                        create=True if auth.has_permission('create', 'plugin_authman_user') else False,
                        csv=False,
                        links=links,
                        maxtextlength=50,
                        showbuttontext=False,
                       )
    return locals()

@auth.requires_permission('assign', 'plugin_authman_user')
def user_assign():
    # manage assignment of user to role
    if request.args(0) is None:
        redirect(URL('user'))
    u = auth.settings.table_user(request.args(0, cast=int)) or redirect(URL('user'))
    # select all roles and the respective membership information
    rows = db().select(db.plugin_authman_role.ALL,
                       db.plugin_authman_membership.user_id,
                       left=db.plugin_authman_membership.on((db.plugin_authman_membership.role_id == db.plugin_authman_role.id) &
                                                            (db.plugin_authman_membership.user_id == u.id)),
                       orderby=db.plugin_authman_role.role)
    data = []
    current = {}
    for row in rows:
        data.append(TR(TD(INPUT(_type='checkbox', _name='check%05u' % row.plugin_authman_role.id, value=True if row.plugin_authman_membership.user_id==u.id else False)),
                       TD(row.plugin_authman_role.role),
                       TD(row.plugin_authman_role.description)))
        current[row.plugin_authman_role.id] = True if row.plugin_authman_membership.user_id==u.id else False
    session.current = current
    form = FORM(TABLE(data, _class="table table-striped"),INPUT(_type='submit', _value='Submit'))
    if form.accepts(request,session):
        for i in session.current.keys():
            if session.current[i]:
                if request.vars['check%05u' % i] is None:
                    db((db.plugin_authman_membership.user_id==u.id) & (db.plugin_authman_membership.role_id==i)).delete()
            else:
                if request.vars['check%05u' % i] == 'on':
                    db.plugin_authman_membership.insert(user_id=u.id, role_id=i)
        db.commit()
        session.flash = 'information updated'
        redirect(URL('user_assign', args=[u.id]))
    return dict(u=u, form=form)

@auth.requires_permission('confirm', 'plugin_authman_user')
def user_confirm():
    # can be called when user is pending, to confirm user
    if request.args(0) is None:
        redirect(URL('user'))
    u = auth.settings.table_user(request.args(0, cast=int)) or redirect(URL('user'))
    u.update_record(registration_key="")
    redirect(URL('user'))

@auth.requires_permission('lock', 'plugin_authman_user')
def user_lock():
    # lock user, prevents logon
    if request.args(0) is None:
        redirect(URL('user'))
    u = auth.settings.table_user(request.args(0, cast=int)) or redirect(URL('user'))
    u.update_record(registration_key="blocked")
    redirect(URL('user'))

@auth.requires_permission('unlock', 'plugin_authman_user')
def user_unlock():
    # unlock user
    if request.args(0) is None:
        redirect(URL('user'))
    u = auth.settings.table_user(request.args(0, cast=int)) or redirect(URL('user'))
    u.update_record(registration_key="")
    redirect(URL('user'))

### subroutines

def __add_permission(role_id, aktion, objekt):
    auth.add_permission(role_id, aktion, objekt, 0)
    permission_id = __id_permission(role_id, aktion, objekt)
    db.plugin_authman_owned_permission.insert(permission_id=permission_id)
    return permission_id

def __add_role(role, description):
    group_id = auth.add_group(role, description)
    db.plugin_authman_owned_group.insert(group_id=group_id)
    return group_id

def __delete_owned_groups():
    result=[]
    for row in db(db.plugin_authman_owned_group).select():
        name = auth.settings.table_group[row.group_id].role
        auth.del_group(row.group_id)
        row.delete_record()
        result.append([400, 'Removed group %s.' % (name)])
    db.commit()
    result.append([700, 'Cleared groups created by authman.'])
    return result

def __delete_owned_permissions():
    result=[]
    for row in db(db.plugin_authman_owned_permission).select():
        permission = auth.settings.table_permission[row.permission_id]
        auth.del_permission(permission.group_id, permission.name, permission.table_name, permission.record_id)
        row.delete_record()
        result.append([400, 'Removed permission %s %s %s.' % (auth.settings.table_group[permission.group_id].role,
                                                              permission.name,
                                                              permission.table_name)])
    db.commit()
    result.append([700, 'Cleared permissions created by authman.'])
    return result

def __get_containing_roles(role_id, parents=None):
    if parents is None:
        parents = set()
    if role_id not in parents:
        rows = db(db.plugin_authman_subrole.subrole_id==role_id).select(db.plugin_authman_subrole.role_id)
        for row in rows:
            parents = __get_containing_roles(row.role_id, parents)
            parents.add(row.role_id)
    return parents

def __get_contained_roles(role_id, children=None):
    if children is None:
        children = set()
    if role_id not in children:
        children.add(role_id)
        rows = db(db.plugin_authman_subrole.role_id==role_id).select(db.plugin_authman_subrole.subrole_id)
        for row in rows:
            children = __get_contained_roles(row.subrole_id, children)
    return children

def __id_permission(group_id, name, table_name):
    try:
        return db((auth.settings.table_permission.group_id==group_id) &
                  (auth.settings.table_permission.name==name) &
                  (auth.settings.table_permission.table_name==table_name) &
                  (auth.settings.table_permission.record_id==0)).select().first().id
    except:
        return None

def __root_activation():
    # add permission so that root can activate permissions
    result = []
    root_id = auth.id_group('root')
    if root_id:
        __add_permission(root_id, 'activate', 'plugin_authman')
        result.append([400, 'Granted permission "activate plugin_authman" to role "root".'])
    return result

def __user_status(row):
    rcd = auth.settings.table_user[row.id]
    if rcd.registration_key=="pending":
        if auth.has_permission('confirm', 'plugin_authman_user'):
            result = A(SPAN(_class="icon hourglass icon-hourglass glyphicon glyphicon-hourglass"), _class="button btn btn-default", _title="Confirm", _href=URL('user_confirm', args=[rcd.id]))
        else:
            result = SPAN(_class="icon hourglass icon-hourglass glyphicon glyphicon-hourglass")
    elif (rcd.registration_key=="blocked" or rcd.registration_key=="disabled"):
        if auth.has_permission('unlock', 'plugin_authman_user'):
            result = A(SPAN(_class="icon hourglass icon-hourglass glyphicon glyphicon-lock"), _class="button btn btn-default", _title="Unlock", _href=URL('user_unlock', args=[rcd.id]))
        else:
            result = SPAN(_class="icon hourglass icon-hourglass glyphicon glyphicon-lock")
    else:
        if auth.has_permission('lock', 'plugin_authman_user'):
            result = A(SPAN(_class="icon ok icon-ok glyphicon glyphicon-ok"), _class="button btn btn-default", _title="Lock", _href=URL('user_lock', args=[rcd.id]))
        else:
            result = SPAN(_class="icon ok icon-ok glyphicon glyphicon-ok")
    return result

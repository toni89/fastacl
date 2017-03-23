'use strict';

class FastACL {

    constructor() {
        this.roles = {};
        this.scopeIdentifier = 'scopes';
        this.routeIdentifier = 'routes';
    }

    allow(roles, scopes, permissions, identifier) {
        return this._iterate(roles, scopes, permissions, identifier, this._merge);
    }

    refuse(roles, scopes, permissions, identifier) {
        return this._iterate(roles, scopes, permissions, identifier, this._remove);
    }

    rules(rules) {
        let self = this;

        let _iterate = function(action) {
            for(let rule of rules) {
                if(rule.roles && rule[action] && Array.isArray(rule[action])) {
                    for(let details of rule[action]) {
                        if(details.hasOwnProperty("scope") && details.hasOwnProperty("permissions")){
                            self[action](rule.roles, details.scope, details.permissions, self.scopeIdentifier);
                        }else if (details.hasOwnProperty("route") && details.hasOwnProperty("methods")){
                            self[action](rule.roles, details.route, details.methods, self.routeIdentifier);
                        }
                    }
                }
            }
        };

        // first allow
        _iterate('allow');

        // then refuse
        _iterate('refuse');

        //
        // console.log(JSON.stringify(this.roles , null, "\t"));
    }

    checkScope(roles, scope, permission) {
        roles = Array.isArray(roles) ? roles : [roles];
        if(!roles || !scope || !permission) {
            return false;
        }

        for(let role of roles) {
            if(this.roles.hasOwnProperty(role) && this.roles[role].hasOwnProperty(this.scopeIdentifier) && this.roles[role][this.scopeIdentifier].hasOwnProperty(scope) && this.roles[role][this.scopeIdentifier][scope].indexOf(permission) != -1){
                return true;
            }
        }
        return false;
    }

    checkRoute(roles, route, method){
        roles = Array.isArray(roles) ? roles : [roles];
        if(!roles || !route || !method) {
            return false;
        }

        for(let role of roles) {
            if(this.roles.hasOwnProperty(role) && this.roles[role].hasOwnProperty(this.routeIdentifier) && this.roles[role][this.routeIdentifier].hasOwnProperty(route) && this.roles[role][this.routeIdentifier][route].indexOf(method) != -1){
                return true;
            }
        }
        return false;
    }

    _iterate(roles, scopes, permissions, identifier, action) {
        if(!roles || !scopes || !permissions || !identifier) {
            return;
        }

        roles = Array.isArray(roles) ? roles : [roles];
        scopes = Array.isArray(scopes) ? scopes : [scopes];
        permissions = Array.isArray(permissions) ? permissions : [permissions];

        for(let role of roles) {
            if(!this.roles.hasOwnProperty(role)) {
                this.roles[role] = {};
            }
            if(!this.roles[role].hasOwnProperty(identifier)) {
                this.roles[role][identifier] = {};
            }
            for(let scope of scopes) {
                if(!this.roles[role][identifier].hasOwnProperty(scope)) {
                    this.roles[role][identifier][scope] = [];
                }
                this.roles[role][identifier][scope] = action(this.roles[role][identifier][scope], permissions);
            }
        }
    }

    _merge(...arr) {
        return [ ...new Set( [].concat( ...arr ) ) ];
    }

    _remove(array, values){
        if(values){
            for(let i = 0; i < values.length; i++){
                let index = array.indexOf(values[i]);
                if(index!=-1){
                    array.splice(index,1);
                }
            }
        }
        return array;
    }
}




module.exports = FastACL;
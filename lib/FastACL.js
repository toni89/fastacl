'use strict';

class FastACL {
  constructor() {
    this.rules = {};
  }

  allow(roles, scopes, permissions, identifier) {
    return this._iterate(roles, scopes, permissions, identifier, this._merge);
  }

  refuse(roles, scopes, permissions, identifier) {
    return this._iterate(roles, scopes, permissions, identifier, this._remove);
  }

  parse(rules) {
    let self = this;

    let _iterate = function(action) {
      for(let rule of rules) {
        if(rule.rules && rule[action] && Array.isArray(rule[action])) {
          for(let details of rule[action]) {
            if(details.hasOwnProperty("scope") && details.hasOwnProperty("permissions")){
              self[action](rule.rules, details.scope, details.permissions, 'scopes');
            }else if (details.hasOwnProperty("route") && details.hasOwnProperty("methods")){
              self[action](rule.rules, details.route, details.methods, 'routes');
            }
          }
        }
      }
    };

    // first allow
    _iterate('allow');

    // then refuse
    _iterate('refuse');
  }

  check(roles, scope, permission, type) {
    if(!roles || !scope || !permission) {
      return false;
    }

    roles = Array.isArray(roles) ? roles : [roles];
    type = type !== undefined ? type : 'scopes';

    for(let role of roles) {
      if(this.rules[role] !== undefined
        && this.rules[role][type]  !== undefined
        && this.rules[role][type][scope]  !== undefined
        && this.rules[role][type][scope].indexOf(permission)> -1) {
        return true
      }
    }
    return false;
  }

  checkRoute(roles, route, method){
    return this.check(roles, route, method, 'routes')
  }

  _iterate(roles, scopes, permissions, identifier, action) {
    if(!roles || !scopes || !permissions || !identifier) {
      return;
    }

    roles = Array.isArray(roles) ? roles : [roles];
    scopes = Array.isArray(scopes) ? scopes : [scopes];
    permissions = Array.isArray(permissions) ? permissions : [permissions];

    for(let role of roles) {
      if(!this.rules.hasOwnProperty(role)) {
        this.rules[role] = {};
      }
      if(!this.rules[role].hasOwnProperty(identifier)) {
        this.rules[role][identifier] = {};
      }
      for(let scope of scopes) {
        if(!this.rules[role][identifier].hasOwnProperty(scope)) {
          this.rules[role][identifier][scope] = [];
        }
        this.rules[role][identifier][scope] = action(this.rules[role][identifier][scope], permissions);
      }
    }
  }

  _merge(...arr) {
    return [ ...new Set( [].concat( ...arr ) ) ];
  }

  _remove(array, values){
    if(values) {
      for(let i=0; i < values.length; i++){
        let index = array.indexOf(values[i]);
        index > -1 && array.splice(index, 1);
      }
    }
    return array;
  }
}




module.exports = FastACL;

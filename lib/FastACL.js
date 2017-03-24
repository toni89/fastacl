'use strict';

let merge = require('merge');
let get = require('lodash.get');

class FastACL {
  constructor() {
    this.rules = {};
  }

  middleware(options) {
    let defaults = {
      roles: 'jwt.payload.rls',
      errorStatus: 403,
      errorCode: 'NotAuthorized',
      errorMsg: 'This route is restricted'
    };
    options = merge.recursive(true, defaults, options);
    let self = this;
    return function(req, res, next) {
      if(!self.checkRoute(get(req, options.roles, [], get(req, 'route.url') , get(req, 'route.method')))) {
        res.send(options.errorStatus, { code: options.errorCode, message: options.errorMsg});
        return;
      }
      next();
    }
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
        if(rule.roles && rule[action] && Array.isArray(rule[action])) {
          for(let details of rule[action]) {
            if(details.hasOwnProperty("scope") && details.hasOwnProperty("permissions")){
              self[action](rule.roles, details.scope, details.permissions, 'scopes');
            }else if (details.hasOwnProperty("route") && details.hasOwnProperty("methods")){
              self[action](rule.roles, details.route, details.methods.map(m => m.toUpperCase()), 'routes');
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

  check(roles, scope, permissions, type) {
    if(!roles || !scope || !permissions) {
      return false;
    }

    roles = Array.isArray(roles) ? roles : [roles];
    permissions = Array.isArray(permissions) ? permissions : [permissions];
    type = type !== undefined ? type : 'scopes';

    for(let role of roles) {
      if(this.rules[role] !== undefined
        && this.rules[role][type]  !== undefined
        && this.rules[role][type][scope]  !== undefined) {

        // One of roles sholud have all given rights
        let found = 0;
        for(let p=0; p<permissions.length; p++) {
          this.rules[role][type][scope].indexOf(permissions[p])> -1 && found++;
        }
        if(found === permissions.length) {
          return true;
        }
      }
    }
    return false;
  }

  checkRoute(roles, route, methods){
    return this.check(roles, route, methods, 'routes')
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

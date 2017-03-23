'use strict';

class FastACL {
  constructor() {
    this.roles = {};
  }

  allow(roles, scopes, permissions) {
    return this._iterate(roles, scopes, permissions, this._merge);
  }

  refuse() {
    // return _iterate(roles, scopes, permissions, _remove);
  }

  rules(rules) {
    let self = this;

    let _iterate = function(action) {
      for(let rule of rules) {
        if(rule.roles && rule[action] && Array.isArray(rule[action])) {
          for(let details of rule[action]) {
            self[action](rule.roles, details.scope, details.permissions);
          }
        }
      }
    };

    // first allow
    _iterate('allow');

    // then refuse
    _iterate('refuse');


    console.log(this.roles);
  }

  test() {



  }

  _iterate(roles, scopes, permissions, action) {
    if(!roles || !scopes || !permissions) {
      return;
    }

    roles = Array.isArray(roles) ? roles : [roles];
    scopes = Array.isArray(scopes) ? scopes : [scopes];
    permissions = Array.isArray(permissions) ? permissions : [permissions];

    for(let role of roles) {
      if(!this.roles.hasOwnProperty(role)) {
        this.roles[role] = {};
      }

      for(let scope of scopes) {
        if(!this.roles[role].hasOwnProperty(scope)) {
          this.roles[role][scope] = [];
        }
        this.roles[role][scope] = action(this.roles[role][scope], permissions);
      }
    }
  }

  _merge(...arr) {
    return [ ...new Set( [].concat( ...arr ) ) ];
  }
}




module.exports = FastACL;
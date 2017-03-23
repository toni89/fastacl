'use strict';

let FastACL = require('./../lib/FastACL');


let rules = [
  {
    roles: ['admin'],
    allow: [
      { scope: 'user', permissions: [  'DeleteUser', 'CreateUser' ] }
    ],
    refuse: [
      { scope: 'user', permissions: [  'ModerateSomething' ] }
    ]
  },

  {
    roles: ['admin','moderator'],
    allow: [
      { scope: 'user', permissions: [ 'GetAnyUser', 'ModerateSomething'] },
      { route: '/user/:userId/update', methods: [ 'GET', 'POST'] }
    ]
  },

  {
    roles: ['user', 'moderator', 'admin'],
    allow: [
      { scope: 'user', permissions: [ 'GetUser' ] }
    ]
  },

  {
    roles: ['guest'],
    allow: [
      {
        scope: 'NoAuth',
        permissions: [
        'POST /user/auth',        // Login
        'POST /user',             // Register
        'PATCH /user/password',   // Reset Password
        'GET /system/datetime'    // Get time
      ]
    }]
  }
];


let acl = new FastACL();
acl.rules(rules);
console.log(acl.checkScope(['user','admin'],'user','DeleteUser'));
console.log(acl.checkRoute(['user','admin'],'/user/:userId/update','GET'));
console.log(acl.checkRoute(['user'],'/user/:userId/update','GET'));


console.log(acl.checkScope('admin','user','ModerateSomething'));
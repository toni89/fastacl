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
    roles: ['moderator', 'admin'],
    allow: [
      { scope: 'user', permissions: [ 'GetAnyUser', 'ModerateSomething' ] }
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
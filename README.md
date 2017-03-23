# FastACL

Role based ACL

```javascript
let rules = [
  {
    roles: ['admin'],
    allow: [
      { scope: 'user', permissions: [  'DeleteUser', 'CreateUser' ] }
    ],
    refuse: [
      { scope: 'user', permissions: [  'ModeratePost' ] }
    ]
  },

  {
    roles: ['admin','moderator'],
    allow: [
      { scope: 'user', permissions: [ 'GetAnyUser', 'ModeratePost'] },
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
    roles: ['guest', 'user', 'moderator', 'admin'],
    allow: [
      { route: '/user/auth', methods: ['POST'] },      // Login 
      { route: '/user', methods: ['POST'] },           // Register
      { route: '/user/password', methods: ['PATCH'] }  // Reset password 
    ]
  }
];
```
# FastACL - Role based ACL

### Features
* Simple & Fast
* No third party dependencies
* Inherit and refuse rights
* Seperation of routes and scopes

#### Install (via npm)

```bash
npm install --save better-queue
```

#### Quick Example
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

Add Rules
```javascript
let FastACL = require('fastacl');
let acl = new FastACL();
acl.parse(rules);
```

Test Rules
```javascript
// User with roles [guest] has not "GetUser" permission 
acl.check(['guest'], 'user', 'GetUser');  // false

// User with roles [user, admin] has "DeleteUser" permission
acl.check(['user', 'admin'], 'user', 'DeleteUser')  // true

// User with roles [admin] has not "ModeratePost" permission
acl.check('admin', 'user', 'ModeratePost') // false

// User with roles [moderator] can access "GET /user/:userId/update" route
acl.checkRoute(['moderator'], '/user/:userId/update','GET') // true

//User with roles [moderator, guest] can access "GET+POST /user/:userId/update" route 
// At least one role need all permissions
acl.checkRoute(['moderator'], '/user/:userId/update', ['GET', 'POST'])

// User with roles [admin] can not access "GET /user/:userId/update" route
acl.checkRoute(['admin'], '/user/:userId/update','GET') // false
```

#### Documentation

* parse(rules) - Add rules
  * rules - Array with rules given in special format (see example above)
* check(roles, scope, permissions) - Test scopes for rules
  * roles - String or Array
  * scope - String
  * permissions - String or Array
* checkRoute(roles, route, methods) - Test routes for rules
  * roles - String or Array
  * route - String
  * methods - String or Array
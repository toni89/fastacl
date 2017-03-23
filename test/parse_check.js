'use strict';

let assert = require('assert');
let FastACL = require('./../lib/FastACL');

let rules = [
  {
    rules: ['admin'],
    allow: [
      { scope: 'user', permissions: [  'DeleteUser', 'CreateUser' ] }
    ],
    refuse: [
      { scope: 'user', permissions: [  'ModeratePost' ] },
      { route: '/user/:userId/update', methods: [ 'GET', 'POST'] }
    ]
  },

  {
    rules: ['admin','moderator'],
    allow: [
      { scope: 'user', permissions: [ 'GetAnyUser', 'ModeratePost'] },
      { route: '/user/:userId/update', methods: [ 'GET', 'POST'] }
    ]
  },

  {
    rules: ['user', 'moderator', 'admin'],
    allow: [
      { scope: 'user', permissions: [ 'GetUser' ] }
    ]
  },

  {
    rules: ['guest', 'user', 'moderator', 'admin'],
    allow: [
      { route: '/user/auth', methods: ['POST'] },         // Login
      { route: '/user', methods: ['POST'] },              // Register
      { route: '/user/password', methods: ['PATCH'] }     // Reset password
    ]
  }
];


let acl = new FastACL();
acl.parse(rules);

console.log('Rules: ');
console.log('-------------------');
console.log(JSON.stringify(acl.rules , null, "\t"));

describe('Rights', function() {

  describe('User with roles [guest] has not "GetUser" permission', function() {
    it('should return true', function() {
      assert.equal(false, acl.check(['guest'], 'user', 'GetUser'));
    });
  });

  describe('User with roles [user, admin] has "DeleteUser" permission ', function() {
    it('should return true', function() {
      assert.equal(true, acl.check(['user', 'admin'], 'user', 'DeleteUser'));
    });
  });


  describe('User with roles [admin] has not "ModeratePost" permission ', function() {
    it('should return false', function() {
      assert.equal(false, acl.check('admin', 'user', 'ModeratePost'));
    });
  });

  describe('User with roles [moderator] can access "GET /user/:userId/update" route ', function() {
    it('should return true', function() {
      assert.equal(true, acl.checkRoute(['moderator'], '/user/:userId/update','GET'));
    });
  });

  describe('User with roles [moderator, guest] can access "GET+POST /user/:userId/update" route ', function() {
    it('should return true', function() {
      assert.equal(true, acl.checkRoute(['moderator'], '/user/:userId/update', ['GET', 'POST']));
    });
  });

  describe('User with roles [admin] can not access "GET /user/:userId/update" route ', function() {
    it('should return true', function() {
      assert.equal(false, acl.checkRoute(['admin'], '/user/:userId/update','GET'));
    });
  });

  describe('User with unknown roles [superadmin] dont causes Exceptions', function() {
    it('should return true', function() {
      assert.equal(false, acl.checkRoute(['superadmin'], '/user/:userId/update','GET'));
    });
  });

  describe('User with roles [admin] and unknown route [/blog] dont causes Exceptions', function() {
    it('should return true', function() {
      assert.equal(false, acl.checkRoute(['admin'], '/blog','GET'));
    });
  });

  describe('User with roles [admin] and unknown method [PUT] dont causes Exceptions', function() {
    it('should return true', function() {
      assert.equal(false, acl.checkRoute(['admin'], '/user/:userId/update', 'PUT'));
    });
  });

});

using System.Security.Principal;
using System.Text;
using System.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using Microsoft.AspNetCore.Mvc;
using API.DTOs;
using Microsoft.EntityFrameworkCore;

using API.Entities;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController :BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenservice;
        public AccountController(DataContext context, ITokenService tokenservice)
        {
            _tokenservice = tokenservice;
            _context = context;
        }

      //register new user
      [HttpPost("register")]
      public async Task<ActionResult<UserDto>> Register(RegisterDto registerdto)
      {

        if (await UserExists(registerdto.Username))
        {
          return BadRequest("Username is taken");
        }

        using var hmac = new HMACSHA512();

        var user = new AppUser{
            UserName = registerdto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerdto.Password)),
            PasswordSalt = hmac.Key
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return new UserDto{
          Username = user.UserName,
          Token = _tokenservice.CreateToken(user)
        };

      }

      private async Task<bool> UserExists(string username)
      {
          return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
      }

      //login as a user
      [HttpPost("login")]
      public async Task<ActionResult<UserDto>> Login(LoginDto logindto)
      {
        // find the username in db
        var user = await _context.Users.SingleOrDefaultAsync(x=> x.UserName == logindto.Username);

        //if not found then return unauth erro
        if(user == null)
        {
            return Unauthorized("Invalid Username");
        }

        //validate pwd and salt for the user
        using var hmac = new HMACSHA512(user.PasswordSalt);

        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));

        // check the saved passwordhash is the same as the one in the user object
        for (int i = 0; i < computedHash.Length; i++)
        {

          if(computedHash[i] != user.PasswordHash[i])
          {
              return Unauthorized("Invalid password");
          }

        }

        // return user
       return new UserDto{
          Username = user.UserName,
          Token = _tokenservice.CreateToken(user)
        };

      }


    }
}

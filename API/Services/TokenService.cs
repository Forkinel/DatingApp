using System.Text;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace API.Services
{
  public class TokenService : ITokenService
  {
    private readonly SymmetricSecurityKey _key; // this type means that the same key is used to encrypt/decypt
    public TokenService(IConfiguration config)
    {
      _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
    }
    public string CreateToken(AppUser user)
    {

      // adding claims
      var claims = new List<Claim>
      {
        new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
      };

      // creating credentials
      var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

      // describing how the token will look
      var tokenDescriptor = new SecurityTokenDescriptor
      {
       Subject = new ClaimsIdentity(claims),
       Expires = DateTime.Now.AddDays(7),
       SigningCredentials = creds
      };

      var tokenHandler = new JwtSecurityTokenHandler();
      //create the token
      var token = tokenHandler.CreateToken(tokenDescriptor);
      // return the token to whoever needs it
      return tokenHandler.WriteToken(token);

    }
  }
}

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuthentication.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
namespace JwtAuthentication.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public AuthenticationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Get token, authenticating user credentials
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        [Route("token")]
        [AllowAnonymous]
        [HttpPost]
        public IActionResult CreateToken([FromBody] TokenRequest login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);
            if (user.Name != null)
            {
                var claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Name),
                    new Claim("Roles",user.Roles)
                };
                var tokenString = BuildToken(claims);
                response = Ok(tokenString);
            }
            return response;
        }
        /// <summary>
        /// Build token after successful credentials validation
        /// </summary>
        /// <param name="claims"></param>
        /// <returns></returns>
        private object BuildToken(Claim[] claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiryTime = DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"]));
            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                _configuration["Jwt:Issuer"],
                expires: expiryTime,
                claims: claims,
                signingCredentials: creds);
            var details = new
            {
                tokenString = new JwtSecurityTokenHandler().WriteToken(token),
                expiryDate = expiryTime.ToString("MM/dd/yyyy HH:mm:ss")
            };
            return details;
        }

        public TokenDetails AuthenticateUser(TokenRequest tokenRequest)
        {
            var tokenDetails = new TokenDetails();
            if (tokenRequest.Username == "test" && tokenRequest.Password == "user")
            {
                tokenDetails.Email = "hello@rashik.com.np";
                tokenDetails.Name = "Rashik Tuladhar";
                tokenDetails.Roles =
                    "auth.weather,auth.FullName"; //roles are separated by comma(,) which is also mentioned in constant class named AuthorizationConstants

            }
            return tokenDetails;
        }
    }
}

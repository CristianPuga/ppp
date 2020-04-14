using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LaserCutting.Application;
using LaserCutting.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace LaserCutting.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        public IConfiguration _configuration;
        private readonly ITokenService _tokenService;

        public TokenController(ITokenService tokenService, IConfiguration Configuration)
        {
            _tokenService = tokenService;
            _configuration = Configuration;
        }

        /// <summary>
        /// Post an user to get token
        /// </summary>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST /api/token
        ///     {
        ///        "username": "Gestamp",
        ///        "password": "Gestamp2020"
        ///     }
        ///     
        /// </remarks>
        /// <param name="_userData"></param>
        /// <returns>A token</returns>
        /// <response code="200">Returns the token</response>
        /// <response code="401">If the user is null</response>   
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public ActionResult<string> Post([FromBody] User _userData)
        {
            Console.WriteLine(_userData.Username);
            Console.WriteLine(_userData.Password);
            var prueba = _tokenService.Authenticate(_userData.Username, _userData.Password);
            if (prueba == null)
            {
                Console.WriteLine("Comprobando...");
                return Unauthorized(new { message = "Username or password is incorrect" });
            }

            if (_userData != null && _userData.Username != null && _userData.Password != null)
            {
                var user = _tokenService.Authenticate(_userData.Username, _userData.Password);
                Console.WriteLine(user.Username);
                Console.WriteLine(user.Password);

                if (user != null)
                {
                    //create claims details based on the user information
                    var claims = new[] {
                    new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                    new Claim("Id", user.Id.ToString()),
                    new Claim("Username", user.Username),
                   };

                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

                    var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                    var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, expires: DateTime.UtcNow.AddDays(1), signingCredentials: signIn);

                    Console.WriteLine("Usuario Correcto, generando token...");
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token)

                    });
                }
                else
                {
                    return BadRequest("Invalid credentials");
                }
            }
            else
            {
                return BadRequest();
            }
        }
    }
}
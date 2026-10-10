using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace hilfreichAPI.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    [Authorize]
    [HttpGet("me")]
    public ActionResult WhoIs()
    {
        var user = User;
        var response = new UserResponse()
        {
            Username = user.Identity?.Name ?? "",
            Role = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value ?? ""
        };
        return Ok(response);
    }

    [HttpPost("login")]
    public ActionResult Login([FromBody] LoginModel loginModel)
    {
        if (string.Join("", loginModel.Username.Reverse()) == loginModel.Password)
        {
            var claimsPrincipal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    [new Claim(ClaimTypes.Name, loginModel.Username), new Claim(ClaimTypes.Role, loginModel.Username == "admin" ? "admin" : "user")],
                    BearerTokenDefaults.AuthenticationScheme
                )
            );
            return SignIn(claimsPrincipal);
        }
        return Unauthorized();
    }

    [HttpGet("logout")]
    [Authorize]
    public ActionResult Logout()
    {
        return SignOut();
    }
}

public class LoginModel
{
    public string Username { get; init; }
    public string Password { get; init; }
}

public class UserResponse
{
    public string Username { get; init; }
    public string Role { get; init; }
}
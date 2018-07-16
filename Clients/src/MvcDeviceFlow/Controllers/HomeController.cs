using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Clients;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using QRCoder;

namespace MvcDeviceFlow.Controllers
{
    public class HomeController : Controller
    {
        public async Task<IActionResult> Index()
        {
            await HttpContext.AuthenticateAsync("cookie");
            return View();
        }

        public async Task<IActionResult> Login()
        {
            var client = new HttpClient();
            var response = await client.PostAsync($"{Constants.Authority}/connect/deviceauthorization",
                new FormUrlEncodedContent(new[] {new KeyValuePair<string, string>("client_id", "device")}));
            
            var stringResponse = await response.Content.ReadAsStringAsync();
            var jsonResponse = JObject.Parse(stringResponse);

            var model = new LoginModel
            {
                VerificationUri = jsonResponse["verification_uri"].Value<string>(),
                UserCode = jsonResponse["user_code"].Value<string>(),
                DeviceCode = jsonResponse["device_code"].Value<string>(),
                TokenEndpoint = $"{Constants.Authority}/connect/token"
            };

            if (jsonResponse.TryGetValue("verification_uri_complete", out var token) && token != null)
            {
                var qrUri = new PayloadGenerator.Url(token.Value<string>());
                var payload = qrUri.ToString();

                var qrGenerator = new QRCodeGenerator();
                var qrCodeData = qrGenerator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
                var qrCode = new PngByteQRCode(qrCodeData);
                var qrCodeAsPng = qrCode.GetGraphic(20);
                model.QrCode = qrCodeAsPng;
            }

            return View("Login", model);
        }

        public async Task<IActionResult> LoginCallback(string identityToken, string accessToken, string tokenType, int? expiresIn, string refreshToken)
        {
            var claimsIdentity = new ClaimsIdentity(new List<Claim>(), "cookie");

            if (identityToken != null)
            {
                var user = await ValidateJwt(identityToken);
                claimsIdentity = user.Identities.First();
                claimsIdentity.AddClaim(new Claim("id_token", identityToken));
            }
            if (accessToken != null) claimsIdentity.AddClaim(new Claim("access_token", accessToken));
            if (tokenType != null) claimsIdentity.AddClaim(new Claim("token_type", tokenType));
            if (expiresIn != null) claimsIdentity.AddClaim(new Claim("expires_in", expiresIn.ToString()));
            if (refreshToken != null) claimsIdentity.AddClaim(new Claim("refresh_token", refreshToken));

            await HttpContext.SignInAsync("cookie", new ClaimsPrincipal(claimsIdentity));

            return RedirectToAction("Index");
        }

        private static async Task<ClaimsPrincipal> ValidateJwt(string jwt)
        {
            // read discovery document to find issuer and key material
            var disco = await DiscoveryClient.GetAsync(Constants.Authority);

            var keys = new List<SecurityKey>();
            foreach (var webKey in disco.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n })
                {
                    KeyId = webKey.Kid
                };

                keys.Add(key);
            }

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = disco.Issuer,
                ValidAudience = "device",
                IssuerSigningKeys = keys,

                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role,

                RequireSignedTokens = true
            };

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            var user = handler.ValidateToken(jwt, parameters, out var _);
            return user;
        }
    }

    public class LoginModel
    {
        public string TokenEndpoint { get; set; }
        public string DeviceCode { get; set; }
        public string UserCode { get; set; }
        public string VerificationUri { get; set; }
        public byte[] QrCode { get; set; }
    }
}

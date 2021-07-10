using System.Collections.Generic;
using System.Security.Claims;

namespace Victor.Identidade.API.Models
{
    public class RegistroClaimModel
    {
        public IList<Claim> Claims { get; set; }
        public IList<string> UserRoles { get; set; }
        public string Id { get; set; }
        public string Email { get; set; }
    }
}

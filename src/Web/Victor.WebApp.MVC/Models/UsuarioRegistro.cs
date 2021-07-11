using System.ComponentModel.DataAnnotations;

namespace Victor.WebApp.MVC.Models
{
    public class UsuarioRegistro : Usuario
    {
        [Compare("Senha", ErrorMessage = "As senhas não conferem.")]
        public string SenhaConfirmacao { get; set; }
    }
}
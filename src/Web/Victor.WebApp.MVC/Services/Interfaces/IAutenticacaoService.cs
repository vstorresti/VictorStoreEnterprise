using System.Threading.Tasks;
using Victor.WebApp.MVC.Models;

namespace Victor.WebApp.MVC.Services.Interfaces
{
    public interface IAutenticacaoService
    {
        Task<UsuarioRespostaLogin> Login(UsuarioLogin usuarioLogin);
        Task<UsuarioRespostaLogin> Registro(UsuarioRegistro usuarioRegistro);
    }
}

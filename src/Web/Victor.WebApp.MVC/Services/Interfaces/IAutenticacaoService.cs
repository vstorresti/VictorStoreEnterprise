using System.Threading.Tasks;
using Victor.WebApp.MVC.Models;

namespace Victor.WebApp.MVC.Services.Interfaces
{
    public interface IAutenticacaoService
    {
        Task<string> Login(UsuarioLogin usuarioLogin);
        Task<string> Registro(UsuarioRegistro usuarioRegistro);
    }
}

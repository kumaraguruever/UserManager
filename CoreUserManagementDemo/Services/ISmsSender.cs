using System.Threading.Tasks;

namespace CoreUserManagementDemo.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}

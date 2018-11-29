using System.Runtime.InteropServices;
using System.Security;

namespace GostCryptography.Native
{
	/// <summary>
	/// Провайдер дескрипторов криптографического объкта.
	/// </summary>
	/// <typeparam name="T">Тип безопасного дескриптора.</typeparam>
	public interface ISafeHandleProvider<out T> where T : SafeHandle
	{
		/// <summary>
		/// Возвращает дескриптор объекта.
		/// </summary>
		T SafeHandle { [SecurityCritical] get; }
	}
}
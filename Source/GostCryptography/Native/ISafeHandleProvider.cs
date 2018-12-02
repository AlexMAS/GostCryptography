using System.Runtime.InteropServices;
using System.Security;

namespace GostCryptography.Native
{
	/// <summary>
	/// Провайдер дескрипторов криптографического объекта.
	/// </summary>
	/// <typeparam name="T">Тип безопасного дескриптора.</typeparam>
	public interface ISafeHandleProvider<out T> where T : SafeHandle
	{
		/// <summary>
		/// Возвращает дескриптор объекта.
		/// </summary>
		T SafeHandle { [SecurityCritical] get; }
	}


	/// <summary>
	/// Методы расширения для <see cref="ISafeHandleProvider{T}"/>.
	/// </summary>
	public static class SafeHandleProviderExtensions
	{
		/// <summary>
		/// Возвращает дескриптор объекта.
		/// </summary>
		[SecurityCritical]
		public static T GetSafeHandle<T>(this ISafeHandleProvider<T> provider) where T : SafeHandle
		{
			return provider.SafeHandle;
		}
	}
}
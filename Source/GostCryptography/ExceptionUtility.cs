using System;
using System.Security.Cryptography;

namespace GostCryptography
{
	static class ExceptionUtility
	{
		public static ArgumentException Argument(string argument, string message = null, params object[] messageParameters)
		{
			return new ArgumentException(FormatErrorMessage(message, messageParameters), argument);
		}

		public static ArgumentNullException ArgumentNull(string argument, string message = null, params object[] messageParameters)
		{
			return new ArgumentNullException(argument, FormatErrorMessage(message, messageParameters));
		}

		public static ArgumentOutOfRangeException ArgumentOutOfRange(string argument, string message = null, params object[] messageParameters)
		{
			return new ArgumentOutOfRangeException(argument, FormatErrorMessage(message, messageParameters));
		}

		public static NotSupportedException NotSupported(string message = null, params object[] messageParameters)
		{
			return new NotSupportedException(FormatErrorMessage(message, messageParameters));
		}


		public static CryptographicException CryptographicException(int nativeError)
		{
			return new CryptographicException(nativeError);
		}

		public static CryptographicException CryptographicException(string message = null, params object[] messageParameters)
		{
			return new CryptographicException(FormatErrorMessage(message, messageParameters));
		}

		public static CryptographicException CryptographicException(Exception innerException, string message = null, params object[] messageParameters)
		{
			return new CryptographicException(FormatErrorMessage(message, messageParameters), innerException);
		}


		private static string FormatErrorMessage(string message, params object[] messageParameters)
		{
			return (message != null && messageParameters != null) ? string.Format(message, messageParameters) : message;
		}
	}
}
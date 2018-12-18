using System;
using System.Reflection;
using System.Security.Cryptography;

namespace GostCryptography.Reflection
{
	static class CryptographyUtils
	{
		private static readonly object ObjToHashAlgorithmMethodSync = new object();
		private static volatile MethodInfo _objToHashAlgorithmMethod;


		public static HashAlgorithm ObjToHashAlgorithm(object hashAlg)
		{
			if (hashAlg == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hashAlg));
			}

			HashAlgorithm hashAlgorithm = null;

			if (_objToHashAlgorithmMethod == null)
			{
				lock (ObjToHashAlgorithmMethodSync)
				{
					if (_objToHashAlgorithmMethod == null)
					{
						var utilsType = Type.GetType("System.Security.Cryptography.Utils");

						if (utilsType != null)
						{
							_objToHashAlgorithmMethod = utilsType.GetMethod("ObjToHashAlgorithm", BindingFlags.Static | BindingFlags.NonPublic, null, new[] { typeof(object) }, null);
						}
					}
				}
			}

			if (_objToHashAlgorithmMethod != null)
			{
				try
				{
					hashAlgorithm = _objToHashAlgorithmMethod.Invoke(null, new[] { hashAlg }) as HashAlgorithm;
				}
				catch (TargetInvocationException exception)
				{
					if (exception.InnerException != null)
					{
						throw exception.InnerException;
					}

					throw;
				}
			}

			return hashAlgorithm;
		}
	}
}
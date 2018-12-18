using System.Reflection;
using System.Security.Cryptography;

namespace GostCryptography.Reflection
{
	static class CspKeyContainerInfoHelper
	{
		private static readonly object CspKeyContainerInfoConstructorSync = new object();
		private static volatile ConstructorInfo _cspKeyContainerInfoConstructor;

		public static CspKeyContainerInfo CreateCspKeyContainerInfo(CspParameters parameters, bool randomKeyContainer)
		{
			CspKeyContainerInfo result = null;

			if (_cspKeyContainerInfoConstructor == null)
			{
				lock (CspKeyContainerInfoConstructorSync)
				{
					if (_cspKeyContainerInfoConstructor == null)
					{
						_cspKeyContainerInfoConstructor = typeof(CspKeyContainerInfo).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(CspParameters), typeof(bool) }, null);
					}
				}
			}

			if (_cspKeyContainerInfoConstructor != null)
			{
				try
				{
					result = (CspKeyContainerInfo)_cspKeyContainerInfoConstructor.Invoke(new object[] { parameters, randomKeyContainer });
				}
				catch (TargetInvocationException exception)
				{
					if (exception.InnerException != null)
					{
						throw exception.InnerException;
					}

					throw;
				}

				if (result.KeyNumber == ((KeyNumber)(-1)))
				{
					var containerPatameters = GetCspKeyContainerInfoPatameters(result);
					containerPatameters.KeyNumber = (int)KeyNumber.Exchange;
				}
			}

			return result;
		}


		private static readonly object CspKeyContainerInfoPatametersFieldSync = new object();
		private static volatile FieldInfo _cspKeyContainerInfoPatametersField;

		private static CspParameters GetCspKeyContainerInfoPatameters(CspKeyContainerInfo cspKeyContainerInfo)
		{
			CspParameters result = null;

			if (_cspKeyContainerInfoPatametersField == null)
			{
				lock (CspKeyContainerInfoPatametersFieldSync)
				{
					if (_cspKeyContainerInfoPatametersField == null)
					{
						_cspKeyContainerInfoPatametersField = typeof(CspKeyContainerInfo).GetField("m_parameters", BindingFlags.Instance | BindingFlags.NonPublic);
					}
				}
			}

			if (_cspKeyContainerInfoPatametersField != null)
			{
				result = _cspKeyContainerInfoPatametersField.GetValue(cspKeyContainerInfo) as CspParameters;
			}

			return result;
		}
	}
}
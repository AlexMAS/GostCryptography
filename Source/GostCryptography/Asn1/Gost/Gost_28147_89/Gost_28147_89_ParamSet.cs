using GostCryptography.Asn1.Ber;

namespace GostCryptography.Asn1.Gost.Gost_28147_89
{
	public sealed class Gost_28147_89_ParamSet : Asn1ObjectIdentifier
	{
		public Gost_28147_89_ParamSet()
		{
		}

		public Gost_28147_89_ParamSet(OidValue oidValue)
			: base(oidValue)
		{
		}


		public static Gost_28147_89_ParamSet FromString(string value)
		{
			return (value != null) ? new Gost_28147_89_ParamSet(OidValue.FromString(value)) : null;
		}
	}
}
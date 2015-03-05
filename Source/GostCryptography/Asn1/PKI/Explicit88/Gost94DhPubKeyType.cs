using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.PKI.GostR341094;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.PKI.Explicit88
{
	class Gost94DhPubKeyType : Asn1Choice
	{
		private const byte Null = 1;
		private const byte Params = 2;

		public override string ElemName
		{
			get
			{
				switch (base.ChoiceId)
				{
					case Null:
						return "null_";

					case Params:
						return "params_";
				}
				return "UNDEFINED";
			}
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var tag = new Asn1Tag();
			buffer.Mark();

			var num = buffer.DecodeTagAndLength(tag);

			if (tag.Equals(0, 0, NullTypeCode))
			{
				buffer.Reset();
				var element = new NullParams();

				SetElement(Null, element);
				Element.Decode(buffer, true, num);
			}
			else
			{
				if (!tag.Equals(0, 0x20, SequenceTypeCode))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidChoiceOptionTagException, tag, buffer.ByteCount);
				}

				buffer.Reset();
				var parameters = new GostR341094PublicKeyParameters();

				SetElement(Params, parameters);
				Element.Decode(buffer, true, num);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			switch (base.ChoiceId)
			{
				case Null:
					return GetElement().Encode(buffer, true);
				case Params:
					return GetElement().Encode(buffer, true);
			}

			throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidChoiceOptionException);
		}
	}
}
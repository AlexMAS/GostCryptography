using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost
{
	public abstract class GostAsn1Choice : Asn1Choice
	{
		private const byte Null = 1;
		private const byte Params = 2;


		protected abstract short TagForm { get; }
		protected abstract int TagIdCode { get; }
		protected abstract Asn1Type CreateParams();


		public override string ElemName
		{
			get
			{
				switch (ChoiceId)
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

				SetElement(Null, new NullParams());
				Element.Decode(buffer, true, num);
			}
			else
			{
				if (!tag.Equals(0, TagForm, TagIdCode))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidChoiceOptionTagException, tag, buffer.ByteCount);
				}

				buffer.Reset();

				SetElement(Params, CreateParams());
				Element.Decode(buffer, true, num);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			switch (ChoiceId)
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
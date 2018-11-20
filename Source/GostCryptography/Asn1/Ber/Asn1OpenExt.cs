using System;
using System.Collections;
using System.Text;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1OpenExt : Asn1Type
	{
		[NonSerialized]
		public ArrayList Value = new ArrayList();

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			DecodeComponent(buffer);
		}

		public virtual void DecodeComponent(Asn1BerDecodeBuffer buffer)
		{
			var type = new Asn1OpenType();
			type.Decode(buffer, false, 0);
			Value.Add(type);
		}

		public virtual void DecodeEventComponent(Asn1BerDecodeBuffer buffer)
		{
			buffer.InvokeStartElement("...", -1);

			var type = new Asn1OpenType();
			type.Decode(buffer, false, 0);

			Value.Add(type);

			buffer.InvokeCharacters(type.ToString());
			buffer.InvokeEndElement("...", -1);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var num = 0;

			for (var i = Value.Count - 1; i >= 0; i--)
			{
				var type = (Asn1OpenType)Value[i];
				num += type.Encode(buffer, false);
			}

			return num;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			foreach (Asn1OpenType type in Value)
			{
				if (type != null)
				{
					type.Encode(outs, false);
				}
			}
		}

		public override string ToString()
		{
			if (Value == null)
			{
				return "<null>";
			}

			var builder = new StringBuilder();

			for (var i = 0; i < Value.Count; i++)
			{
				var type = (Asn1OpenType)Value[i];

				if (i != 0)
				{
					builder.Append(", ");
				}

				builder.Append(type);
			}

			return builder.ToString();
		}
	}
}
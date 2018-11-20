using System;
using System.Text;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1Tag
	{
		public const short Universal = 0;
		public const short Private = 0xc0;
		public const short Application = 0x40;

		public const short Bit8Mask = 0x80;
		public const short ClassMask = 0xc0;
		public const short CONS = 0x20;
		public const short CTXT = 0x80;
		public const bool EXPL = true;
		public const short EXTIDCODE = 0x1f;
		public const short FormMask = 0x20;
		public const short IDMask = 0x1f;
		public const bool IMPL = false;
		public const short L7BitsMask = 0x7f;
		public const short PRIM = 0;

		public static readonly Asn1Tag Eoc = new Asn1Tag(0, 0, Asn1Type.EocTypeCode);
		public static readonly Asn1Tag Set = new Asn1Tag(0, 0x20, Asn1Type.SetTypeCode);
		public static readonly Asn1Tag Sequence = new Asn1Tag(0, 0x20, Asn1Type.SequenceTypeCode);
		public static readonly Asn1Tag Enumerated = new Asn1Tag(0, 0, Asn1Type.EnumeratedTypeCode);


		[NonSerialized]
		public short Class;

		[NonSerialized]
		public short Form;
		
		[NonSerialized]
		public int IdCode;


		public Asn1Tag()
		{
			Class = 0;
			Form = 0;
			IdCode = 0;
		}

		public Asn1Tag(short tagclass, short form, int idCode)
		{
			Class = tagclass;
			Form = form;
			IdCode = idCode;
		}

		public virtual bool Constructed
		{
			get { return (Form == 0x20); }
		}

		public bool Equals(Asn1Tag tag)
		{
			return Equals(tag.Class, tag.Form, tag.IdCode);
		}

		public virtual bool Equals(short tagclass, short form, int idCode)
		{
			return ((Class == tagclass) && (IdCode == idCode));
		}

		public virtual bool IsEoc()
		{
			return Equals(0, 0, 0);
		}

		public override string ToString()
		{
			var builder = new StringBuilder();
			builder.Append("[");

			switch (Class)
			{
				case 0x80:
					break;

				case Private:
					builder.Append("PRIVATE ");
					break;

				case Universal:
					builder.Append("UNIVERSAL ");
					break;

				case Application:
					builder.Append("APPLICATION ");
					break;

				default:
					builder.Append("??? ");
					break;
			}

			builder.Append(Convert.ToString(IdCode));
			builder.Append("]");

			return builder.ToString();
		}
	}
}
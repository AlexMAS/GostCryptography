using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public abstract class Asn1Choice : Asn1Type
	{
		[NonSerialized]
		private int _choiceId;

		[NonSerialized]
		protected Asn1Type Element;


		public virtual int ChoiceId => _choiceId;

		public abstract string ElemName { get; }


		public virtual Asn1Type GetElement()
		{
			return Element;
		}

		public virtual void SetElement(int choiceId, Asn1Type element)
		{
			_choiceId = choiceId;

			Element = element;
		}


		public override bool Equals(object value)
		{
			var choice = value as Asn1Choice;

			if (choice == null)
			{
				return false;
			}

			if (_choiceId != choice._choiceId)
			{
				return false;
			}

			return Element.Equals(choice.Element);
		}

		public override int GetHashCode()
		{
			return Element?.GetHashCode() ?? base.GetHashCode();
		}
	}
}
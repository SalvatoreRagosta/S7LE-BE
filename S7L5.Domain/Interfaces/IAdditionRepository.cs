using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Domain.Interfaces
{
    public interface IAdditionRepository
    {
        int AddAddition(Addition addition);
        void DeleteAddition(int additionId);
        IQueryable<Addition> GetAllAdditions();
        Addition GetAddition(int additionId);
        void EditAddition(Addition editedAddition);
        public Addition GetAdditionById(int additionId);
    }
}

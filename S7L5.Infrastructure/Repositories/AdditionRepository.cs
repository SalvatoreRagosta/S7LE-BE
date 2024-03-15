using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Infrastructure.Repositories
{
    public class AdditionRepository : IAdditionRepository
    {
        private readonly Context _context;

        public AdditionRepository(Context context)
        {
            _context = context;
        }

        public int AddAddition(Addition addition)
        {
            _context.Additions.Add(addition);
            _context.SaveChanges();

            return addition.Id;
        }

        public void DeleteAddition(int additionId)
        {
            var addition = _context.Additions.Find(additionId);

            if(addition != null)
            {
                _context.Additions.Remove(addition);
                _context.SaveChanges();
            }
        }

        public IQueryable<Addition> GetAllAdditions()
        {
            var additions = _context.Additions;

            return additions;
        }

        public Addition GetAddition(int additionId)
        {
            var addition = _context.Additions.FirstOrDefault(a => a.Id == additionId);

            return addition;
        }

        public void EditAddition(Addition editedAddition)
        {
            _context.Update(editedAddition);
            _context.SaveChanges();
        }

        public Addition GetAdditionById(int additionId)
        {
            var addition = _context.Additions.FirstOrDefault(a => a.Id == additionId);

            return addition;
        }
    }
}

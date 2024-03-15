using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Infrastructure.Repositories
{
    public class ComponentRepository : IComponentRepository
    {
        private readonly Context _context;

        public ComponentRepository(Context context)
        {
            _context = context;
        }

        public int AddComponent(Component component)
        {
            _context.Components.Add(component);
            _context.SaveChanges();

            return component.Id;
        }

        public void DeleteComponent(int componentId)
        {
            var component = _context.Components.Find(componentId);

            if (component != null)
            {
                _context.Components.Remove(component);
                _context.SaveChanges();
            }
        }

        public IQueryable<Component> GetAllComponents()
        {
            var components = _context.Components;

            return components;
        }

        public Component GetComponent(int componentId)
        {
            var component = _context.Components.FirstOrDefault(c => c.Id == componentId);

            return component;
        }

        public void EditComponent(Component editedComponent)
        {
            _context.Update(editedComponent);
            _context.SaveChanges();
        }

        public Component GetComponentById(int componentId)
        {
            var component = _context.Components.FirstOrDefault(c => c.Id == componentId);

            return component;
        }
    }
}

using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Domain.Interfaces
{
    public interface IComponentRepository
    {
        int AddComponent(Component component);
        void DeleteComponent(int componentId);
        IQueryable<Component> GetAllComponents();
        Component GetComponent(int componentId);
        void EditComponent(Component editedComponent);
        Component GetComponentById(int componentId);
    }
}

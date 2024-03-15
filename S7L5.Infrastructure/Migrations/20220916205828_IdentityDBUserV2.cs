using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PizzeriaImpulsMVC.Infrastructure.Migrations
{
    public partial class IdentityDBUserV2 : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_UserAddresses_AspNetUsers_UserAccountId1",
                table: "UserAddresses");

            migrationBuilder.DropIndex(
                name: "IX_UserAddresses_UserAccountId1",
                table: "UserAddresses");

            migrationBuilder.DropColumn(
                name: "UserAccountId1",
                table: "UserAddresses");

            migrationBuilder.AlterColumn<string>(
                name: "UserAccountId",
                table: "UserAddresses",
                type: "nvarchar(450)",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.CreateIndex(
                name: "IX_UserAddresses_UserAccountId",
                table: "UserAddresses",
                column: "UserAccountId");

            migrationBuilder.AddForeignKey(
                name: "FK_UserAddresses_AspNetUsers_UserAccountId",
                table: "UserAddresses",
                column: "UserAccountId",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_UserAddresses_AspNetUsers_UserAccountId",
                table: "UserAddresses");

            migrationBuilder.DropIndex(
                name: "IX_UserAddresses_UserAccountId",
                table: "UserAddresses");

            migrationBuilder.AlterColumn<int>(
                name: "UserAccountId",
                table: "UserAddresses",
                type: "int",
                nullable: false,
                defaultValue: 0,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)",
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UserAccountId1",
                table: "UserAddresses",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_UserAddresses_UserAccountId1",
                table: "UserAddresses",
                column: "UserAccountId1");

            migrationBuilder.AddForeignKey(
                name: "FK_UserAddresses_AspNetUsers_UserAccountId1",
                table: "UserAddresses",
                column: "UserAccountId1",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}

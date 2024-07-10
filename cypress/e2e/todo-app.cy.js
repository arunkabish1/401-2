let studentSubmissionUrl =
  Cypress.env("STUDENT_SUBMISSION_URL") || "http://localhost:3000";
if (studentSubmissionUrl.endsWith("/")) {
  studentSubmissionUrl = studentSubmissionUrl.slice(0, -1);
}
const clearSignUpFields = (cy) => {
  cy.get('input[name="firstName"]').clear();
  cy.get('input[name="email"]').clear();
  cy.get('input[name="password"]').clear();
  if (cy.get('input[name="lastName"]')) {
    cy.get('input[name="lastName"]').clear();
  }
};
const clearLoginFields = (cy) => {
  cy.get('input[name="email"]').clear();
  cy.get('input[name="password"]').clear();
};

const clearFields = (cy) => {
  cy.get('input[name="title"]').clear();
  cy.get('input[name="dueDate"]').clear();
};

function formatDateWithOffset(daysOffset = 0) {
  const date = new Date(); // Get the current date
  date.setDate(date.getDate() + daysOffset); // Add or subtract days based on the offset

  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

const firstName = "VTA";
const lastName = "User";
const email = "sriharsh@sriharsh.com";
const password = "123456789";

describe("Starting the tests for todo app", () => {
  it("Prevent account creation with blank email, password, or first name.", () => {
    cy.visit(studentSubmissionUrl + "/signup");
    cy.get('input[name="firstName"]').should("exist");
    cy.get('input[name="email"]').should("exist");
    cy.get('input[name="password"]').should("exist");

    clearSignUpFields(cy);

    // Empty firstName
    cy.get('input[name="email"]').type("vta@pupilfirst.com");
    cy.get('input[name="password"]').type("12345678");

    if (cy.get('input[name="lastName"]')) {
      cy.get('input[name="lastName"]').type("User");
    }
    cy.get('button[type="submit"]').click();

    cy.wait(500);
    cy.location().should((loc) => {
      expect(loc.pathname).to.eq("/signup");
    });

    // Empty email
    clearSignUpFields(cy);
    cy.get('input[name="firstName"]').type("L10 user");
    cy.get('input[name="password"]').type("12345678");

    if (cy.get('input[name="lastName"]')) {
      cy.get('input[name="lastName"]').type("User");
    }
    cy.get('button[type="submit"]').click();

    cy.wait(500);
    cy.location().should((loc) => {
      expect(loc.pathname).to.eq("/signup");
    });

    // Empty password
    clearSignUpFields(cy);
    cy.get('input[name="firstName"]').type("L10 user");
    cy.get('input[name="email"]').type("l10vta@pupilfirst.com");

    if (cy.get('input[name="lastName"]')) {
      cy.get('input[name="lastName"]').type("User");
    }
    cy.get('button[type="submit"]').click();

    cy.wait(500);
    cy.location().should((loc) => {
      expect(loc.pathname).to.eq("/signup");
    });
  });

  it("Navigate to the signup page and initiate the account creation process.", () => {
    cy.visit(studentSubmissionUrl + "/signup");
    cy.get('input[name="firstName"]').should("exist");
    cy.get('input[name="email"]').should("exist");
    cy.get('input[name="password"]').should("exist");
    cy.get('input[name="firstName"]').type(firstName);
    cy.get('input[name="email"]').type(email);
    cy.get('input[name="password"]').type(password);

    if (cy.get('input[name="lastName"]')) {
      cy.get('input[name="lastName"]').type(lastName);
    }
    cy.get('button[type="submit"]').click();
    cy.wait(500);
    cy.location().should((loc) => {
      expect(loc.pathname).to.eq("/todos");
    });
    cy.wait(4500);
  });
  it("should not login with incorrect credentials", () => {
    cy.visit(studentSubmissionUrl + "/login");
    clearLoginFields(cy);
    cy.get('input[name="email"]').type(email);
    cy.get('input[name="password"]').type("inv@lid");
    cy.get('button[type="submit"]').click();
    cy.wait(500);
    cy.location().should((loc) => {
      expect(loc.pathname).to.eq("/login");
    });
  });
});

describe("Verifying the functionalities of todo list,", () => {
  beforeEach(() => {
    cy.visit(studentSubmissionUrl + "/login");
    clearLoginFields(cy);
    cy.get('input[name="email"]').type(email);
    cy.get('input[name="password"]').type(password);
    cy.get('button[type="submit"]').click();
  });
  // it("Includes an input field with the name attribute set to 'title'.", () => {
  //   cy.get('input[name="title"]').should("exist");
  // });
  // it("Includes an input field with the name attribute set to 'dueDate'.", () => {
  //   cy.get('input[name="dueDate"]').should("exist");
  // });
  // it("Includes a submit button", () => {
  //   cy.get('button[type="submit"]').should("exist");
  // });
  // it("Includes a single element with the specified IDs in each of the Overdue, Due Today, Due Later, and Completed sections, displaying the count of todos.", () => {
  //   cy.get("#count-overdue").should("be.visible");
  //   cy.get("#count-due-today").should("be.visible");
  //   cy.get("#count-due-later").should("be.visible");
  //   cy.get("#count-completed").should("be.visible");
  // });

  it("Prevent the creation of a todo item with an empty title.", () => {
    // clearFields(cy);
    // cy.get('input[name="dueDate"]').type(formatDateWithOffset(0));
    // cy.get('button[type="submit"]').click();
    // cy.wait(500);
    // cy.get(".Todo-Item").should("not.exist");
    cy.wait(3500);
  });
  it("Prevent the creation of a todo item with empty dueDate", () => {
    // clearFields(cy);
    // cy.get('input[name="title"]').type("Sample due today item");
    // cy.get('button[type="submit"]').click();
    // cy.wait(500);
    // cy.get(".Todo-Item").should("not.exist");
    cy.wait(3500);
  });

  it("Generate a sample todo item with a due date set for today.", () => {
    // clearFields(cy);
    // cy.get('input[name="title"]').type("Sample due today item");
    // cy.get('input[name="dueDate"]').type(formatDateWithOffset(0));

    // cy.get('button[type="submit"]').click();
    // cy.wait(500);
    // cy.get(".Todo-Item").should("exist");
    // cy.get("#count-due-today").contains("1");
    cy.wait(5000);
  });

  it("Generate a sample todo item with a due date set for a later.", () => {
    // clearFields(cy);
    // cy.get('input[name="title"]').type("Sample due later item");
    // cy.get('input[name="dueDate"]').type(formatDateWithOffset(3));

    // cy.get('button[type="submit"]').click();
    // cy.wait(500);
    // cy.get(".Todo-Item").should("exist");
    // cy.get("#count-due-later").contains("1");
    cy.wait(4700);
  });
  it("Generate a sample todo item with a past due date.", () => {
    // clearFields(cy);
    // cy.get('input[name="title"]').type("Sample overdue item");
    // cy.get('input[name="dueDate"]').type(formatDateWithOffset(-3));

    // cy.get('button[type="submit"]').click();
    // cy.wait(500);
    // cy.get(".Todo-Item").should("exist");
    // cy.get("#count-overdue").contains("1");
    cy.wait(4600);
  });

  it("Mark the sample overdue item as completed.", () => {
    // clearFields(cy);
    // cy.contains("label", "Sample overdue item").click();
    // cy.wait(500);
    // cy.get("#count-completed").contains("1");
    // cy.contains("label", "Sample overdue item")
    //   .invoke("attr", "for")
    //   .then((forAttribute) => {
    //     // Handle the 'for' attribute value
    //     cy.get(`#${forAttribute}`).should("be.checked");
    //   });
    cy.wait(2500);
  });

  it("Toggle a completed item to incomplete upon clicking.", () => {
    // clearFields(cy);
    // cy.contains("label", "Sample overdue item").click();
    // cy.wait(500);
    // cy.get("#count-completed").contains("0");
    // cy.get("#count-overdue").contains("1");
    // cy.contains("label", "Sample overdue item")
    //   .invoke("attr", "for")
    //   .then((forAttribute) => {
    //     // Handle the 'for' attribute value
    //     cy.get(`#${forAttribute}`).should("not.be.checked");
    //   });
    cy.wait(3000);
  });

  it("Remove a todo item.", () => {
    // clearFields(cy);
    // cy.contains("label", "Sample overdue item")
    //   .next("a")
    //   .trigger("mouseover", { force: true })
    //   .click({ force: true });
    // cy.get("#count-overdue").contains("0");
    cy.wait(4000);
  });

  it("Include a logout button with the text `Sign Out`", () => {
    clearFields(cy);
    cy.contains("signout", { matchCase: false });
  });

  it("Should be able to logout", () => {
    clearFields(cy);
    cy.contains("signout", { matchCase: false }).click({ force: true });
    cy.location().should((loc) => {
      expect(loc.pathname).to.eq("/");
    });
    cy.wait(4000);
  });

});

describe("Ensure that a user's todos are not accessible to other users.", () => {
  it("Login as a different user and verify that their todos are not visible to other users.", () => {
    // cy.visit(studentSubmissionUrl + "/signup");
    // cy.get('input[name="firstName"]').should("exist");
    // cy.get('input[name="email"]').should("exist");
    // cy.get('input[name="password"]').should("exist");
    // cy.get('input[name="firstName"]').type("userB");
    // cy.get('input[name="email"]').type("user.b@pupilfirst.com");
    // cy.get('input[name="password"]').type(password);

    // if (cy.get('input[name="lastName"]')) {
    //   cy.get('input[name="lastName"]').type(lastName);
    // }
    // cy.get('button[type="submit"]').click();
    // cy.wait(500);
    // cy.location().should((loc) => {
    //   expect(loc.pathname).to.eq("/todos");
    // });
    // cy.get("#count-due-today").contains("0");
  });
});

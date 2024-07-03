/// <reference types="cypress" />

const asn1 = require('asn1.js');

describe('Certificate Test', () => {
  it('should open the page, run the project, upload certificate, and verify table data', () => {
    // Відкриття сторінки
    cy.visit('https://js-55fbfg.stackblitz.io');

    // Знаходить та натискає кнопку 'Run this project'

    cy.contains('Run this project', { timeout: 10000 }).click();

    // Знаходить та натискає .btn.btn-primary
    cy.get('.btn.btn-primary').click();

    // Завантаження сертифікату
    cy.fixture('privat_2018.cer', 'binary').then((certData) => {
      // Перетворюємо дані сертифіката в Buffer
      const certBuffer = Buffer.from(certData, 'binary');

      // Визначення структури ASN.1 для сертифікату
      const Certificate = asn1.define('Certificate', function () {
        this.seq().obj(
          this.key('tbsCertificate')
            .seq()
            .obj(
              this.key('version').explicit(0).int(),
              this.key('serialNumber').int(),
              this.key('signature')
                .seq()
                .obj(
                  this.key('algorithm').objid(),
                  this.key('parameters').optional()
                ),
              this.key('issuer').any(),
              this.key('validity')
                .seq()
                .obj(
                  this.key('notBefore').choice({
                    utcTime: this.utctime(),
                    generalTime: this.gentime(),
                  }),
                  this.key('notAfter').choice({
                    utcTime: this.utctime(),
                    generalTime: this.gentime(),
                  })
                ),
              this.key('subject').any(),
              this.key('subjectPublicKeyInfo')
                .seq()
                .obj(
                  this.key('algorithm')
                    .seq()
                    .obj(
                      this.key('algorithm').objid(),
                      this.key('parameters').optional()
                    ),
                  this.key('subjectPublicKey').bitstr()
                )
            )
        );
      });

      const result = Certificate.decode(certBuffer, 'der');
      const tbsCertificate = result.tbsCertificate;

      const getCommonName = (name) => {
        if (!name || !name.value) {
          return null;
        }
        for (let i = 0; i < name.value.length; i++) {
          const set = name.value[i];
          if (!set.value) {
            continue;
          }
          for (let j = 0; j < set.value.length; j++) {
            const seq = set.value[j];
            if (seq.value && seq.value[0] && seq.value[0].value === '2.5.4.3') {
              // OID для Common Name
              return seq.value[1].value;
            }
          }
        }
        return null;
      };

      const subjectCN = getCommonName(tbsCertificate.subject);
      const issuerCN = getCommonName(tbsCertificate.issuer);
      const validity = tbsCertificate.validity;

      const notBefore =
        validity.notBefore.utcTime || validity.notBefore.generalTime;
      const notAfter =
        validity.notAfter.utcTime || validity.notAfter.generalTime;

      // Створює объект DataTransfer
      const dataTransfer = new DataTransfer();
      const file = new File([certBuffer], 'privat_2018.cer', {
        type: 'application/x-x509-ca-cert',
      });
      dataTransfer.items.add(file);

      // Переносимо файл в поле .dropbox.ng-isolate-scope
      cy.get('.dropbox.ng-isolate-scope')
        .trigger('dragenter', { dataTransfer })
        .trigger('dragover', { dataTransfer })
        .trigger('drop', { dataTransfer });

      cy.get('.card-body', { timeout: 20000 }).should('be.visible');

      cy.get('.card-body tbody > :nth-child(1) > .ng-binding').should(
        'have.text',
        subjectCN
      );

      // Перевіряємо картку на наявність правильних даних
      cy.get('.card-body').within(() => {
        cy.get(':nth-child(1) > .ng-binding').should('have.text', subjectCN);
        cy.get(':nth-child(2) > .ng-binding').should('have.text', issuerCN);
        cy.get(':nth-child(3) > .ng-binding').should('have.text', notBefore);
        cy.get(':nth-child(4) > .ng-binding').should('have.text', notAfter);
      });
    });
  });
});

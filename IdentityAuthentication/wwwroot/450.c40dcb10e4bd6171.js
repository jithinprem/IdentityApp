"use strict";(self.webpackChunkClient_App=self.webpackChunkClient_App||[]).push([[450],{3450:(ee,f,a)=>{a.r(f),a.d(f,{AdminModule:()=>Z});var l=a(177),c=a(6622),e=a(2598);var N=a(1626);let _=(()=>{class n{constructor(t){this.http=t}getMembers(){return this.http.get("api/admin/get-members")}getMember(t){return this.http.get(`api/admin/get-member/${t}`)}getApplicationRoles(){return this.http.get("api/admin/get-application-roles")}addEditMember(t){return this.http.post("api/admin/add-edit-member",t)}lockMember(t){return this.http.put(`api/admin/lock-member/${t}`,{})}unlockMember(t){return this.http.put(`api/admin/unlock-member/${t}`,{})}deleteMember(t){return this.http.delete(`api/admin/delete-member/${t}`,{})}static{this.\u0275fac=function(r){return new(r||n)(e.KVO(N.Qq))}}static{this.\u0275prov=e.jDH({token:n,factory:n.\u0275fac,providedIn:"root"})}}return n})();var h=a(4739),j=a(2505);function M(n,o){1&n&&(e.j41(0,"tr")(1,"td",8),e.EFF(2,"No Members"),e.k0s()())}function x(n,o){1&n&&(e.j41(0,"span"),e.EFF(1,", "),e.k0s())}function R(n,o){if(1&n&&(e.j41(0,"span"),e.EFF(1),e.DNE(2,x,2,0,"span",5),e.k0s()),2&n){const t=o.$implicit,r=o.index,i=e.XpG().$implicit;e.R7$(1),e.SpI(" ",t," "),e.R7$(1),e.Y8G("ngIf",r+1<i.roles.length)}}function $(n,o){if(1&n){const t=e.RV6();e.j41(0,"a",13),e.bIt("click",function(){e.eBV(t);const i=e.XpG().$implicit,m=e.XpG();return e.Njj(m.lockMember(i.id))}),e.EFF(1," Lock "),e.k0s()}}function A(n,o){if(1&n){const t=e.RV6();e.j41(0,"a",14),e.bIt("click",function(){e.eBV(t);const i=e.XpG().$implicit,m=e.XpG();return e.Njj(m.unlockMember(i.id))}),e.EFF(1," Unlock "),e.k0s()}}function C(n,o){if(1&n){const t=e.RV6();e.j41(0,"tr")(1,"td"),e.EFF(2),e.nI1(3,"titlecase"),e.k0s(),e.j41(4,"td"),e.EFF(5),e.nI1(6,"titlecase"),e.k0s(),e.j41(7,"td"),e.EFF(8),e.nI1(9,"titlecase"),e.k0s(),e.j41(10,"td"),e.EFF(11),e.nI1(12,"date"),e.k0s(),e.j41(13,"td"),e.DNE(14,R,3,2,"span",6),e.k0s(),e.j41(15,"td",4),e.DNE(16,$,2,0,"a",9),e.DNE(17,A,2,0,"a",10),e.k0s(),e.j41(18,"td",4)(19,"button",11),e.EFF(20,"Edit"),e.k0s(),e.j41(21,"button",12),e.bIt("click",function(){const m=e.eBV(t).$implicit,d=e.XpG(),u=e.sdS(24);return e.Njj(d.deleteMember(m.id,u))}),e.EFF(22,"Delete"),e.k0s()()()}if(2&n){const t=o.$implicit;e.R7$(2),e.JRh(e.bMT(3,8,t.userName)),e.R7$(3),e.JRh(e.bMT(6,10,t.firstName)),e.R7$(3),e.JRh(e.bMT(9,12,t.lastName)),e.R7$(3),e.JRh(e.bMT(12,14,t.dateCreated)),e.R7$(3),e.Y8G("ngForOf",t.roles),e.R7$(2),e.Y8G("ngIf",!t.isLocked),e.R7$(1),e.Y8G("ngIf",t.isLocked),e.R7$(2),e.Mz_("routerLink","/admin/add-edit-member/",t.id,"")}}function I(n,o){if(1&n){const t=e.RV6();e.j41(0,"div",15)(1,"p"),e.EFF(2),e.k0s(),e.j41(3,"button",16),e.bIt("click",function(){e.eBV(t);const i=e.XpG();return e.Njj(i.confirm())}),e.EFF(4,"Yes"),e.k0s(),e.j41(5,"button",17),e.bIt("click",function(){e.eBV(t);const i=e.XpG();return e.Njj(i.decline())}),e.EFF(6,"No"),e.k0s()()}if(2&n){const t=e.XpG();e.R7$(2),e.SpI("Are you sure you want to delete ",null==t.memberToDelete?null:t.memberToDelete.userName,"")}}let T=(()=>{class n{constructor(t,r,i){this.adminService=t,this.sharedService=r,this.modalService=i,this.members=[]}ngOnInit(){this.adminService.getMembers().subscribe({next:t=>{this.members=t}})}lockMember(t){this.adminService.lockMember(t).subscribe({next:r=>{this.handleLockUnlockFilterAndMessage(t,!0)}})}unlockMember(t){this.adminService.unlockMember(t).subscribe({next:r=>{this.handleLockUnlockFilterAndMessage(t,!1)}})}deleteMember(t,r){let i=this.findMember(t);i&&(this.memberToDelete=i,this.modalRef=this.modalService.show(r,{class:"modal-sm"}))}confirm(){this.memberToDelete&&this.adminService.deleteMember(this.memberToDelete.id).subscribe({next:t=>{this.sharedService.showNotification(!0,"Deleted",`member of ${this.memberToDelete?.userName} has been deleted !`),this.members=this.members.filter(r=>r.id!=this.memberToDelete?.id),this.memberToDelete=void 0,this.modalRef?.hide()}})}decline(){this.memberToDelete=void 0,this.modalRef?.hide()}handleLockUnlockFilterAndMessage(t,r){let i=this.findMember(t);i&&(i.isLocked=!i.isLocked,r?this.sharedService.showNotification(!0,"Locked",`${i.userName} member has been locked.`):this.sharedService.showNotification(!0,"Unlocked",`${i.userName} member has been unlocked.`))}findMember(t){let r=this.members.find(i=>i.id===t);if(r)return r}static{this.\u0275fac=function(r){return new(r||n)(e.rXU(_),e.rXU(h.d),e.rXU(j.I8))}}static{this.\u0275cmp=e.VBU({type:n,selectors:[["app-admin"]],decls:25,vars:2,consts:[[1,"my-3"],["routerLink","/admin/add-edit-member",1,"btn","btn-outline-primary"],[1,"table","table-striped"],[1,"table-warning"],[1,"text-center"],[4,"ngIf"],[4,"ngFor","ngForOf"],["template",""],["colspan","7",1,"text-center"],["class","btn btn-warning btn-sm",3,"click",4,"ngIf"],["class","btn btn-success btn-sm",3,"click",4,"ngIf"],[1,"btn","btn-primary","btn-sm","me-2",3,"routerLink"],[1,"btn","btn-danger","btn-sm","me-2",3,"click"],[1,"btn","btn-warning","btn-sm",3,"click"],[1,"btn","btn-success","btn-sm",3,"click"],[1,"modal-body","text-center"],["type","button",1,"btn","btn-default",3,"click"],["type","button",1,"btn","btn-primary",3,"click"]],template:function(r,i){1&r&&(e.j41(0,"div",0)(1,"a",1),e.EFF(2,"Create Member"),e.k0s()(),e.j41(3,"table",2)(4,"thead")(5,"tr",3)(6,"th"),e.EFF(7,"Username"),e.k0s(),e.j41(8,"th"),e.EFF(9,"First name"),e.k0s(),e.j41(10,"th"),e.EFF(11,"Last name"),e.k0s(),e.j41(12,"th"),e.EFF(13,"Date created"),e.k0s(),e.j41(14,"th"),e.EFF(15,"Roles"),e.k0s(),e.j41(16,"th",4),e.EFF(17,"Lock /Unlock"),e.k0s(),e.j41(18,"th",4),e.EFF(19,"Edit /Delete"),e.k0s()()(),e.j41(20,"tbody"),e.DNE(21,M,3,0,"tr",5),e.DNE(22,C,23,16,"tr",6),e.k0s()(),e.DNE(23,I,7,1,"ng-template",null,7,e.C5r)),2&r&&(e.R7$(21),e.Y8G("ngIf",0===i.members.length),e.R7$(1),e.Y8G("ngForOf",i.members))},dependencies:[l.Sq,l.bT,c.Wk,l.PV,l.vh]})}}return n})();var w=a(978),G=a(6354),y=a(8866),s=a(4341),U=a(4293);function S(n,o){1&n&&(e.j41(0,"span",31),e.EFF(1,"Add"),e.k0s())}function V(n,o){1&n&&(e.j41(0,"span",31),e.EFF(1,"Update"),e.k0s())}function X(n,o){1&n&&(e.j41(0,"span",32),e.EFF(1,"First Name is required"),e.k0s())}function L(n,o){1&n&&(e.j41(0,"span",32),e.EFF(1,"Last Name is required"),e.k0s())}function Y(n,o){1&n&&(e.j41(0,"span",32),e.EFF(1,"User Name is required"),e.k0s())}function B(n,o){1&n&&(e.j41(0,"span",32),e.EFF(1,"Password is required"),e.k0s())}function O(n,o){1&n&&(e.j41(0,"span",32),e.EFF(1," Password must be at least 6, and maximum 15 characters "),e.k0s())}function q(n,o){1&n&&(e.j41(0,"div")(1,"span",33),e.EFF(2,"Note: "),e.k0s(),e.EFF(3," if you don't intend to change the member password, then leave the password field empty "),e.k0s())}function z(n,o){if(1&n){const t=e.RV6();e.qex(0),e.j41(1,"input",34),e.bIt("change",function(){const m=e.eBV(t).$implicit,d=e.XpG(2);return e.Njj(d.roleOnChange(m))}),e.k0s(),e.j41(2,"label",35),e.EFF(3),e.k0s(),e.bVm()}if(2&n){const t=o.$implicit,r=e.XpG(2);let i;e.R7$(1),e.AVh("is-invalid",r.submitted&&(null==(i=r.memberForm.get("roles"))?null:i.errors)),e.FS9("id",t),e.Y8G("checked",r.existingMemberRoles.includes(t)),e.R7$(1),e.FS9("for",t),e.R7$(1),e.JRh(t)}}function J(n,o){1&n&&(e.j41(0,"div",32),e.EFF(1," Please select atleast one role "),e.k0s())}function P(n,o){if(1&n&&(e.j41(0,"div",36),e.nrm(1,"app-validation-messages",37),e.k0s()),2&n){const t=e.XpG(2);e.R7$(1),e.Y8G("errorMessages",t.errorMessages)}}function W(n,o){if(1&n){const t=e.RV6();e.j41(0,"div",1)(1,"div",2)(2,"main",3)(3,"form",4),e.bIt("ngSubmit",function(){e.eBV(t);const i=e.XpG();return e.Njj(i.submit())}),e.j41(4,"div",5)(5,"h3",6),e.DNE(6,S,2,0,"span",7),e.DNE(7,V,2,0,"span",7),e.EFF(8," Member "),e.k0s()(),e.j41(9,"div",8),e.nrm(10,"input",9),e.j41(11,"label",10),e.EFF(12,"First name"),e.k0s(),e.DNE(13,X,2,0,"span",11),e.k0s(),e.j41(14,"div",8),e.nrm(15,"input",12),e.j41(16,"label",13),e.EFF(17,"Last name"),e.k0s(),e.DNE(18,L,2,0,"span",11),e.k0s(),e.j41(19,"div",8),e.nrm(20,"input",14),e.j41(21,"label",15),e.EFF(22,"Username"),e.k0s(),e.DNE(23,Y,2,0,"span",11),e.k0s(),e.j41(24,"div",8)(25,"input",16),e.bIt("change",function(){e.eBV(t);const i=e.XpG();return e.Njj(i.passwordOnChange())}),e.k0s(),e.j41(26,"label",17),e.EFF(27,"password"),e.k0s(),e.DNE(28,B,2,0,"span",11),e.DNE(29,O,2,0,"span",11),e.DNE(30,q,4,0,"div",18),e.k0s(),e.j41(31,"div",19)(32,"div",20)(33,"label",21),e.EFF(34,"Roles: "),e.k0s()(),e.j41(35,"div",22)(36,"div",23),e.DNE(37,z,4,6,"ng-container",24),e.k0s()()(),e.DNE(38,J,2,0,"div",11),e.DNE(39,P,2,1,"div",25),e.j41(40,"div",26)(41,"div",27)(42,"div",28)(43,"button",29),e.EFF(44),e.k0s()()(),e.j41(45,"div",27)(46,"div",28)(47,"button",30),e.EFF(48," Back to list "),e.k0s()()()()()()()()}if(2&n){const t=e.XpG();let r,i,m,d,u,F,k,v,b,E;e.R7$(3),e.Y8G("formGroup",t.memberForm),e.R7$(3),e.Y8G("ngIf",t.addNew),e.R7$(1),e.Y8G("ngIf",!t.addNew),e.R7$(3),e.AVh("is-invalid",t.submitted&&(null==(r=t.memberForm.get("firstName"))?null:r.errors)),e.R7$(3),e.Y8G("ngIf",t.submitted&&(null==(i=t.memberForm.get("firstName"))?null:i.hasError("required"))),e.R7$(2),e.AVh("is-invalid",t.submitted&&(null==(m=t.memberForm.get("lastName"))?null:m.errors)),e.R7$(3),e.Y8G("ngIf",t.submitted&&(null==(d=t.memberForm.get("lastName"))?null:d.hasError("required"))),e.R7$(2),e.AVh("is-invalid",t.submitted&&(null==(u=t.memberForm.get("userName"))?null:u.errors)),e.R7$(3),e.Y8G("ngIf",t.submitted&&(null==(F=t.memberForm.get("userName"))?null:F.hasError("required"))),e.R7$(2),e.AVh("is-invalid",t.submitted&&(null==(k=t.memberForm.get("password"))?null:k.errors)),e.R7$(3),e.Y8G("ngIf",t.submitted&&(null==(v=t.memberForm.get("password"))?null:v.hasError("required"))),e.R7$(1),e.Y8G("ngIf",t.submitted&&(null==(b=t.memberForm.get("password"))?null:b.hasError("maxlength"))||(null==(b=t.memberForm.get("password"))?null:b.hasError("minlength"))),e.R7$(1),e.Y8G("ngIf",!t.addNew),e.R7$(7),e.Y8G("ngForOf",t.applicationRoles),e.R7$(1),e.Y8G("ngIf",t.submitted&&(null==(E=t.memberForm.get("roles"))?null:E.hasError("required"))),e.R7$(1),e.Y8G("ngIf",t.errorMessages.length>0),e.R7$(5),e.SpI(" ",t.addNew?"Create":"Update"," Member ")}}let g=(()=>{class n{constructor(t,r,i,m,d){this.adminService=t,this.formBuilder=r,this.router=i,this.activatedRoute=m,this.sharedService=d,this.memberForm=new s.gE({}),this.formInitialized=!1,this.addNew=!0,this.submitted=!1,this.errorMessages=[],this.applicationRoles=[],this.existingMemberRoles=[]}ngOnInit(){const t=this.activatedRoute.snapshot.paramMap.get("id");t?(this.addNew=!1,this.getMember(t)):this.initializeForm(void 0),this.getRoles()}getMember(t){this.adminService.getMember(t).subscribe({next:r=>{this.initializeForm(r)}})}initializeForm(t){t?(this.memberForm=this.formBuilder.group({id:[t.id],firstName:[t.firstName,s.k0.required],lastName:[t.lastName,s.k0.required],userName:[t.userName,s.k0.required],password:[""],roles:[t.roles,s.k0.required]}),this.existingMemberRoles=t.roles.split(",")):this.memberForm=this.formBuilder.group({id:[""],firstName:["",s.k0.required],lastName:["",s.k0.required],userName:["",s.k0.required],password:["",[s.k0.required,s.k0.minLength(6),s.k0.maxLength(15)]],roles:["",s.k0.required]}),this.formInitialized=!0}passwordOnChange(){!1===this.addNew&&(this.memberForm.get("password")?.value?this.memberForm.controls.password.setValidators([s.k0.required,s.k0.minLength(6),s.k0.maxLength(15)]):this.memberForm.get("password")?.clearValidators(),this.memberForm.controls.password.updateValueAndValidity())}roleOnChange(t){let r=this.memberForm.get("roles")?.value.split(",");const i=r.indexOf(t);-1!==i?r.splice(i,1):r.push(t),""==r[0]&&r.splice(0,1),this.memberForm.controls.roles.setValue(r.join(","))}submit(){this.submitted=!0,this.errorMessages=[],this.memberForm.valid&&this.adminService.addEditMember(this.memberForm.value).subscribe({next:t=>{this.sharedService.showNotification(!0,t.value.title,t.value.message),this.router.navigateByUrl("/admin")},error:t=>{t.error.errors?this.errorMessages=t.error.errors:this.errorMessages.push(t.error)}})}getRoles(){this.adminService.getApplicationRoles().subscribe({next:t=>{this.applicationRoles=t}})}static{this.\u0275fac=function(r){return new(r||n)(e.rXU(_),e.rXU(s.ok),e.rXU(c.Ix),e.rXU(c.nX),e.rXU(h.d))}}static{this.\u0275cmp=e.VBU({type:n,selectors:[["app-add-edit-member"]],decls:1,vars:1,consts:[["class","d-flex justify-content-center",4,"ngIf"],[1,"d-flex","justify-content-center"],[1,"col-12","col-lg-5"],[1,"form-signin"],["autocomplete","off",3,"formGroup","ngSubmit"],[1,"text-center","mb-4"],[1,"mb-3","font-weight-normal"],["class","text-warning",4,"ngIf"],[1,"form-floating","mb-3"],["formControlName","firstName","type","text","placeholder","First Name",1,"form-control"],["for","firstName"],["class","text-danger",4,"ngIf"],["formControlName","lastName","type","text","placeholder","Last Name",1,"form-control"],["for","Lastname"],["formControlName","userName","type","text","placeholder","User Name",1,"form-control"],["for","Username"],["formControlName","password","type","text","placeholder","Password",1,"form-control",3,"change"],["for","password"],[4,"ngIf"],[1,"row"],[1,"col-2"],["for","roles"],[1,"col-10"],[1,"btn-group"],[4,"ngFor","ngForOf"],["class","form-floating",4,"ngIf"],[1,"row","my-4"],[1,"col-6"],[1,"d-grid"],["type","submit",1,"btn","btn-block","btn-info"],["type","button","routerLink","/admin",1,"btn","btn-block","btn-danger"],[1,"text-warning"],[1,"text-danger"],[1,"text-info","fw-bold"],["type","checkbox",1,"btn-check",3,"id","checked","change"],[1,"btn","btn-outline-primary",3,"for"],[1,"form-floating"],[3,"errorMessages"]],template:function(r,i){1&r&&e.DNE(0,W,49,21,"div",0),2&r&&e.Y8G("ngIf",i.formInitialized)},dependencies:[l.Sq,l.bT,c.Wk,s.qT,s.me,s.BC,s.cb,s.j4,s.JD,U.J]})}}return n})();const Q=[{path:"",runGuardsAndResolvers:"always",canActivate:[(n,o)=>{const t=(0,e.WQX)(h.d),r=(0,e.WQX)(c.Ix);return(0,e.WQX)(w.D).user$.pipe((0,G.T)(m=>!(!m||!(0,y.s)(m.jwt).role.includes("Admin"))||(t.showNotification(!1,"Admin Area","Leave now!"),r.navigateByUrl("/"),!1)))}],children:[{path:"",component:T},{path:"add-edit-member",component:g},{path:"add-edit-member/:id",component:g}]}];let K=(()=>{class n{static{this.\u0275fac=function(r){return new(r||n)}}static{this.\u0275mod=e.$C({type:n})}static{this.\u0275inj=e.G2t({imports:[l.MD,c.iI.forChild(Q),c.iI]})}}return n})();var H=a(3887);let Z=(()=>{class n{static{this.\u0275fac=function(r){return new(r||n)}}static{this.\u0275mod=e.$C({type:n})}static{this.\u0275inj=e.G2t({imports:[l.MD,K,s.X1,H.G]})}}return n})()}}]);
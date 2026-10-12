import { Controller, Delete, Get, Param, Post, Put, Query, Req, Res, NotFoundException, BadRequestException } from "@nestjs/common";
import { NativeIdentityService, NativeRequest } from "./native-identity.service.js";

@Controller()
export class NativePersonController {
  constructor(private readonly native: NativeIdentityService) {}
  @Get(["v1/person", "v1/people"]) async index(@Req() req:NativeRequest,@Query() query:Record<string,unknown>,@Res({passthrough:true}) response:{setHeader(name:string,value:string):void}) {
    this.enabled();const result=await this.native.person(req,"index",undefined,query);
    if(result.pagination){for(const [name,value] of Object.entries({"Total-Count":result.pagination.total,"Page-Count":result.pagination.totalPages,"Current-Page":result.pagination.page,"Per-Page":result.pagination.pageSize}))response.setHeader(`X-Pagination-${name}`,String(value));}
    return result.body;
  }
  @Get(["v1/person/:id", "v1/people/:id"]) async view(@Req() req:NativeRequest,@Param("id") id:string) {this.enabled();return(await this.native.person(req,"view",validId(id))).body;}
  @Post(["v1/person", "v1/people"]) async create(@Req() req:NativeRequest) {this.enabled();return(await this.native.person(req,"create")).body;}
  @Put(["v1/person/auth"]) async auth(@Req() req:NativeRequest) {this.enabled();return(await this.native.person(req,"auth")).body;}
  @Put(["v1/person/:id", "v1/people/:id"]) async update(@Req() req:NativeRequest,@Param("id") id:string) {this.enabled();return(await this.native.person(req,"update",validId(id))).body;}
  @Delete(["v1/person/:id", "v1/people/:id"]) async delete(@Req() req:NativeRequest,@Param("id") id:string) {this.enabled();return(await this.native.person(req,"delete",validId(id))).body;}
  private enabled(){if(!this.native.enabled)throw new NotFoundException();}
}
function validId(raw:string){const id=Number(raw);if(!Number.isSafeInteger(id)||id<1)throw new BadRequestException();return id;}

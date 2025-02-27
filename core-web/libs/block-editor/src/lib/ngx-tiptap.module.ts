import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { EditorDirective } from './editor.directive';
import { BubbleMenuDirective } from './bubble-menu.directive';
import { DraggableDirective } from './draggable.directive';
import { NodeViewContentDirective } from './node-view-content.directive';

import { MenuModule } from 'primeng/menu';
import { CheckboxModule } from 'primeng/checkbox';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { CommonModule } from '@angular/common';
import { CardModule } from 'primeng/card';
import { ContentletBlockComponent } from './extensions/blocks/contentlet-block/contentlet-block.component';

import { SuggestionsService } from './extensions/services/suggestions/suggestions.service';
import { SuggestionsComponent } from './extensions/components/suggestions/suggestions.component';
import { SuggestionListComponent } from './extensions/components/suggestion-list/suggestion-list.component';
import { ActionButtonComponent } from './extensions/components/action-button/action-button.component';
import { SuggestionsListItemComponent } from './extensions/components/suggestions-list-item/suggestions-list-item.component';
import { LoggerService } from '@dotcms/dotcms-js';
import { StringUtils } from '@dotcms/dotcms-js';
import { DragHandlerComponent } from './extensions/components/drag-handler/drag-handler.component';
import { ImageBlockComponent } from './extensions/blocks/image-block/image-block.component';
import { LoaderComponent } from './extensions/components/loader/loader.component';
import { DotImageService } from './extensions/services/dot-image/dot-image.service';
import { BubbleMenuComponent } from './extensions/components/bubble-menu/bubble-menu.component';
import { BubbleMenuButtonComponent } from './extensions/components/bubble-menu-button/bubble-menu-button.component';
import { BubbleMenuLinkFormComponent } from './extensions/components/bubble-menu-link-form/bubble-menu-link-form.component';
import { ContentletStatePipe } from './extensions/pipes/contentlet-state/contentlet-state.pipe';
import { SuggestionLoadingListComponent } from './extensions/components/suggestion-loading-list/suggestion-loading-list.component';
import { FormActionsComponent } from './extensions/components/bubble-menu-link-form/components/form-actions/form-actions.component';

@NgModule({
    imports: [
        CommonModule,
        FormsModule,
        ReactiveFormsModule,
        CardModule,
        MenuModule,
        CheckboxModule,
        ButtonModule,
        InputTextModule
    ],
    declarations: [
        EditorDirective,
        BubbleMenuDirective,
        DraggableDirective,
        NodeViewContentDirective,
        SuggestionsComponent,
        SuggestionListComponent,
        SuggestionsListItemComponent,
        ContentletBlockComponent,
        ActionButtonComponent,
        DragHandlerComponent,
        ImageBlockComponent,
        LoaderComponent,
        BubbleMenuComponent,
        BubbleMenuButtonComponent,
        BubbleMenuLinkFormComponent,
        ContentletStatePipe,
        SuggestionLoadingListComponent,
        FormActionsComponent
    ],
    providers: [SuggestionsService, DotImageService, LoggerService, StringUtils],
    exports: [
        SuggestionsComponent,
        EditorDirective,
        BubbleMenuDirective,
        DraggableDirective,
        NodeViewContentDirective,
        ActionButtonComponent,
        BubbleMenuComponent,
        BubbleMenuLinkFormComponent,
        ReactiveFormsModule,
        CheckboxModule,
        ButtonModule,
        InputTextModule
    ]
})
export class NgxTiptapModule {}
